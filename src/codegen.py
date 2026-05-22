"""
Generate Halmos-compatible Solidity tests from ExtractedSpec.

Usage:
  python -m src.codegen one <finding_id>
  python -m src.codegen all
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from anthropic import Anthropic
from dotenv import load_dotenv
from pydantic import BaseModel
from rich.console import Console
from rich.panel import Panel

from .contract_ctx import (
    contract_name_from_path,
    detect_pragma,
    fetch_source,
    import_path,
    is_curated,
    summarize_source,
)
from .corpus import (
    ROOT,
    load_all_seed_findings,
    load_seed_finding,
    test_contract_name,
    test_dir,
    test_file_path,
)
from .extract import ExtractedSpec

DEFAULT_MODEL = "claude-opus-4-5"
MAX_TOKENS = 4000
METRICS_PATH = ROOT / "results" / "codegen_metrics.json"

console = Console()

REAL_CONTRACT_EXAMPLE = r'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {SetterTopNPoolsStrategy} from "contracts/SetterTopNPoolsStrategy.sol";

/// Dependency stub only — NOT the contract under test.
contract MockAVM {
    uint256 public topN;
    address public executor;
    constructor(address _executor, uint256 _topN) { executor = _executor; topN = _topN; }
}

contract Test2025_05_blackhole_H_10 is Test, SymTest {
    SetterTopNPoolsStrategy strategy;
    address owner;

    function setUp() public {
        owner = makeAddr("owner");
        MockAVM avm = new MockAVM(makeAddr("executor"), 10);
        vm.prank(owner);
        strategy = new SetterTopNPoolsStrategy(makeAddr("voter"), address(avm));
    }

    function check_ownerCanSetTopNPools() public {
        vm.prank(owner);
        address[] memory pools = new address[](0);
        (bool success,) = address(strategy).call(
            abi.encodeWithSelector(SetterTopNPoolsStrategy.setTopNPools.selector, pools)
        );
        assert(success);
    }
}
'''

SYSTEM_PROMPT = f"""You generate Halmos symbolic execution tests for Foundry that compile against REAL protocol repos.

CANONICAL EXAMPLE (imports real contract from repo — NOT a mock copy):
{REAL_CONTRACT_EXAMPLE}

CRITICAL RULES:
- Output ONLY valid Solidity source. No markdown fences.
- Import SymTest from "halmos-cheatcodes/SymTest.sol" (NOT halmos/SymTest.sol).
- Import the REAL target contract: `import {{ContractName}} from "<affected_file_path>";`
- NEVER define a mock/fake/stub copy of the contract under test (no MockVulnerable*, no reimplementing target functions).
- Small dependency stubs (e.g. constructor deps like AVM) are OK if the real repo needs them — keep minimal.
- Inherit Test, SymTest. Exactly ONE `check_*` function.
- Use `svm.createAddress` for symbolic callers and `vm.assume` for constraints.
- Assertion direction: property MUST hold on FIXED code (Halmos PASS), fail on VULNERABLE (Halmos FAIL).
- Match pragma to target contract source when provided.
- Use repo-relative import paths exactly as given (forward slashes).
- Deploy/instantiate the real contract in setUp(); do not test against interfaces only unless unavoidable.
"""


def build_user_prompt(spec: ExtractedSpec, finding, *, source: str | None, contract_name: str | None, imp: str | None) -> str:
    inv = spec.violated_invariant
    return f"""Generate a Halmos test file for this finding.

Finding ID: {spec.finding_id}
Title: {finding.title}
Repo URL: {finding.repo_url}
Affected file: {finding.affected_file}
Import path: {imp}
Contract name: {contract_name}
Vulnerable commit: {finding.vulnerable_commit}
Pragma hint: {detect_pragma(source)}

Extracted spec:
{spec.model_dump_json(indent=2)}

Target function: {spec.function_signature}
Precondition: {inv.precondition if inv else "see spec"}
should_revert: {inv.should_revert if inv else "see spec"}

REAL CONTRACT SOURCE (from repo at vulnerable commit):
{summarize_source(source) if source else "(source unavailable — import from affected file path)"}

Test contract name: {test_contract_name(spec.finding_id)}

Generate the complete .t.sol file. Import the real contract at "{imp}"."""


def strip_solidity_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:solidity)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


MOCK_FORBIDDEN = re.compile(
    r"\bcontract\s+(MockVulnerable\w*|Mock\w*Strategy|Mock\w*Settlement|MockBase\w*)\b",
    re.I,
)


def post_process_code(code: str, *, contract_name: str | None, imp: str | None) -> str:
    code = code.replace('from "halmos/SymTest.sol"', 'from "halmos-cheatcodes/SymTest.sol"')
    code = code.replace("from 'halmos/SymTest.sol'", "from 'halmos-cheatcodes/SymTest.sol'")
    if contract_name and imp:
        import_line = f'import {{{contract_name}}} from "{imp}";'
        if contract_name not in code or imp not in code:
            # Insert after SymTest import
            code = re.sub(
                r'(import \{SymTest\} from "halmos-cheatcodes/SymTest\.sol";\n)',
                r"\1" + import_line + "\n",
                code,
                count=1,
            )
    return code


def validate_solidity(code: str, *, contract_name: str | None, imp: str | None) -> tuple[bool, str]:
    if not code.startswith("// SPDX-License-Identifier"):
        return False, "missing SPDX license identifier"
    if "pragma solidity" not in code:
        return False, "missing pragma solidity"
    if not re.search(r"\bcontract\s+\w+", code):
        return False, "missing contract block"
    if not re.search(r"\bfunction\s+check_\w+", code):
        return False, "missing check_ function"
    if 'from "halmos/SymTest.sol"' in code:
        return False, "wrong SymTest import path"
    if MOCK_FORBIDDEN.search(code):
        return False, "contains forbidden mock copy of target contract"
    if contract_name and imp:
        if contract_name not in code:
            return False, f"missing import/use of real contract {contract_name}"
        if imp not in code:
            return False, f"missing import path {imp}"
    return True, "ok"


class CodegenMetrics(BaseModel):
    generated_at: str
    total: int
    success: int
    failed: int
    skipped_curated: int = 0
    failures: list[dict[str, str]]


def write_metrics(metrics: CodegenMetrics) -> None:
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(metrics.model_dump_json(indent=2) + "\n", encoding="utf-8")


def generate_test(finding_id: str, *, client: Anthropic | None = None) -> Path:
    load_dotenv(ROOT / ".env")
    if is_curated(finding_id):
        path = test_file_path(finding_id)
        if not path.exists():
            raise FileNotFoundError(f"Curated test missing: {path}")
        return path

    spec = ExtractedSpec.load(finding_id)
    finding = load_seed_finding(finding_id)

    if client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        client = Anthropic(api_key=api_key)

    imp = import_path(finding.affected_file)
    cname = contract_name_from_path(finding.affected_file)
    source, _ = fetch_source(finding.repo_url, finding.affected_file, finding.vulnerable_commit)

    user_prompt = build_user_prompt(spec, finding, source=source, contract_name=cname, imp=imp)
    full_prompt = f"SYSTEM:\n{SYSTEM_PROMPT}\n\nUSER:\n{user_prompt}"

    response = client.messages.create(
        model=DEFAULT_MODEL,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    code = strip_solidity_fences(response.content[0].text)
    code = post_process_code(code, contract_name=cname, imp=imp)

    out_dir = test_dir(finding_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "_prompt.txt").write_text(full_prompt, encoding="utf-8")

    ok, reason = validate_solidity(code, contract_name=cname, imp=imp)
    out_path = test_file_path(finding_id)
    out_path.write_text(code + "\n", encoding="utf-8")

    if not ok:
        raise ValueError(f"codegen validation failed: {reason}")

    return out_path


def cmd_one(finding_id: str) -> int:
    t0 = time.perf_counter()
    try:
        path = generate_test(finding_id)
    except Exception as exc:
        console.print(f"[red]FAILED[/red] {finding_id}: {exc}")
        return 1
    elapsed = time.perf_counter() - t0
    code = path.read_text(encoding="utf-8")
    label = "curated" if is_curated(finding_id) else "generated"
    console.print(Panel(code[:2000] + ("\n...(truncated)" if len(code) > 2000 else ""), title=f"{path} ({label})"))
    console.print(f"[green]{label.title()}[/green] {path} ({elapsed:.1f}s)")
    return 0


def cmd_all() -> int:
    load_dotenv(ROOT / ".env")
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]ANTHROPIC_API_KEY not set[/red]")
        return 1
    client = Anthropic(api_key=api_key)

    ok = fail = skip = 0
    failures: list[dict[str, str]] = []
    for finding in load_all_seed_findings():
        spec_path = ROOT / "data" / "specs" / f"{finding.id}.json"
        if not spec_path.exists():
            console.print(f"[yellow]SKIP[/yellow] {finding.id}: no spec")
            fail += 1
            failures.append({"finding_id": finding.id, "reason": "no spec"})
            continue
        if is_curated(finding.id):
            console.print(f"[dim]CURATED[/dim] {finding.id}")
            skip += 1
            continue
        console.print(f"[bold]Codegen[/bold] {finding.id}")
        try:
            generate_test(finding.id, client=client)
            ok += 1
        except Exception as exc:
            console.print(f"[red]FAILED[/red] {finding.id}: {exc}")
            fail += 1
            failures.append({"finding_id": finding.id, "reason": str(exc)})
    metrics = CodegenMetrics(
        generated_at=datetime.now(timezone.utc).isoformat(),
        total=ok + fail + skip,
        success=ok,
        failed=fail,
        skipped_curated=skip,
        failures=failures,
    )
    write_metrics(metrics)
    console.print(f"\n[bold]Done:[/bold] {ok} ok, {fail} failed, {skip} curated (skipped)")
    return 0 if fail == 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="BugMine Halmos test codegen")
    sub = parser.add_subparsers(dest="command", required=True)
    one_p = sub.add_parser("one")
    one_p.add_argument("finding_id")
    sub.add_parser("all")
    args = parser.parse_args()
    if args.command == "one":
        sys.exit(cmd_one(args.finding_id))
    sys.exit(cmd_all())


if __name__ == "__main__":
    main()
