"""
Apply validated specs to unrelated repos to find latent similar bugs.

Usage:
  python -m src.generalize one <finding_id> --targets data/targets/<list>.txt
  python -m src.generalize all --targets data/targets/access_control_pool.txt
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from anthropic import Anthropic
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table

from .corpus import ROOT, load_all_seed_findings, test_file_path
from .extract import ExtractedSpec
from .validate import VALIDATION_DIR, ValidationRecord
from .verify import (
    Outcome,
    detect_test_dir,
    ensure_halmos,
    ensure_solc,
    forge_build,
    forge_install,
    parse_contract_name,
    run_halmos,
)

console = Console()

DEFAULT_MODEL = "claude-opus-4-5"
MAX_TOKENS = 2000
GEN_DIR = ROOT / "data" / "generalize"
RESULTS_DIR = ROOT / "results" / "generalize"
METRICS_PATH = ROOT / "results" / "generalize_metrics.json"
TRIAGE_NOTE = "POTENTIAL — requires human triage"

ADAPT_SYSTEM = """You adapt Halmos property tests to new Solidity contracts.

Rules:
- Preserve the SAME security invariant from the original spec.
- If the invariant clearly does NOT apply to the target contract, respond with exactly: SKIP
- Otherwise output ONLY valid Solidity test file content (SPDX + pragma + imports + one check_ function).
- No markdown fences. No explanation unless SKIP.
- Inherit Test, SymTest. Use svm.createAddress for symbolic callers.
- Import the real target contract from the repo (not mocks) when possible.
"""


class TargetSpec(BaseModel):
    repo_url: str
    ref: str
    name: str


class GeneralizeHit(BaseModel):
    target_repo: str
    target_file: str
    halmos_outcome: Outcome
    counterexample: str | None = None
    adapted_test_path: str | None = None
    note: str = TRIAGE_NOTE


class TargetRunStatus(BaseModel):
    target_name: str
    repo_url: str
    ref: str
    uups_contracts_found: int = 0
    adapted: bool = False
    adapted_contract: str | None = None
    compiled: bool = False
    halmos_outcome: Outcome | None = None
    halmos_completed: bool = False
    skip_reason: str | None = None
    potential: bool = False


class GeneralizeResult(BaseModel):
    finding_id: str
    targets_attempted: int = 0
    targets_with_uups: int = 0
    targets_compiled: int = 0
    targets_halmos_completed: int = 0
    potential_bugs_found: int = 0
    target_statuses: list[TargetRunStatus] = Field(default_factory=list)
    findings: list[GeneralizeHit] = Field(default_factory=list)
    generated_at: str = ""


def load_validation_status(finding_id: str) -> str | None:
    path = VALIDATION_DIR / f"{finding_id}.json"
    if not path.exists():
        return None
    record = ValidationRecord.model_validate_json(path.read_text(encoding="utf-8"))
    return record.status


def parse_targets_file(path: Path) -> list[TargetSpec]:
    targets: list[TargetSpec] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"Invalid target line (expected url:ref): {line}")
        url, ref = line.rsplit(":", 1)
        url = url.strip()
        name = url.rstrip("/").split("/")[-1].replace(".git", "")
        targets.append(TargetSpec(repo_url=url, ref=ref.strip(), name=name))
    return targets


def clone_target(repo_url: str, dest: Path, ref: str) -> None:
    if dest.exists() and (dest / ".git").exists():
        subprocess.run(["git", "fetch", "--all"], cwd=dest, capture_output=True)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", repo_url, str(dest)], check=True, capture_output=True, text=True)
    proc = subprocess.run(["git", "checkout", ref], cwd=dest, capture_output=True, text=True)
    if proc.returncode != 0:
        subprocess.run(["git", "checkout", "main"], cwd=dest, check=False, capture_output=True, text=True)
        subprocess.run(["git", "checkout", "master"], cwd=dest, check=False, capture_output=True, text=True)
    subprocess.run(["git", "submodule", "update", "--init", "--recursive"], cwd=dest, check=False, capture_output=True)


def _skip_path(rel: str) -> bool:
    lowered = rel.replace("\\", "/").lower()
    if lowered.startswith("test/") or lowered.startswith("tests/"):
        return True
    if "/test/" in lowered or "/tests/" in lowered:
        return True
    if "node_modules/" in lowered:
        return True
    if lowered.startswith("script/") or lowered.startswith("scripts/"):
        return True
    return False


def _uses_uups(content: str) -> bool:
    if "UUPSUpgradeable" not in content and "_authorizeUpgrade" not in content:
        return False
    collapsed = re.sub(r"\s+", " ", content)
    inherits = bool(re.search(r"\bis\b[^;{]*UUPSUpgradeable", collapsed))
    defines = bool(re.search(r"\b(?:abstract\s+)?contract\s+\w+[^;{]*UUPSUpgradeable", collapsed))
    has_auth = "_authorizeUpgrade" in content and "function upgradeTo" in content
    return inherits or defines or has_auth


def find_uups_candidates(repo: Path, limit: int = 8) -> list[Path]:
    candidates: list[Path] = []
    for sol in repo.rglob("*.sol"):
        rel = str(sol.relative_to(repo)).replace("\\", "/")
        if _skip_path(rel):
            continue
        try:
            content = sol.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _uses_uups(content):
            continue
        candidates.append(sol)

    def score(p: Path) -> tuple[int, int]:
        rel = str(p.relative_to(repo)).replace("\\", "/").lower()
        penalty = 0
        if rel.startswith("lib/"):
            penalty += 1000
        if "mock" in rel:
            penalty += 500
        return penalty, p.stat().st_size

    candidates.sort(key=score)
    return candidates[:limit]


def adapt_test_with_claude(
    client: Anthropic,
    spec: ExtractedSpec,
    original_test: str,
    target_file: Path,
    target_content: str,
) -> str | None:
    prompt = f"""Original spec:
{spec.model_dump_json(indent=2)}

Original test:
{original_test}

Target file: {target_file.name}
Target content:
{target_content[:12000]}

Adapt the test to this contract. Output SKIP if the spec does not apply."""

    response = client.messages.create(
        model=DEFAULT_MODEL,
        max_tokens=MAX_TOKENS,
        system=ADAPT_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.content[0].text.strip()
    if text.upper().startswith("SKIP"):
        return None
    if text.startswith("```"):
        text = re.sub(r"^```(?:solidity)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    if "check_" not in text or "pragma solidity" not in text:
        return None
    return text.strip()


def save_counterexample(
    finding_id: str,
    target: TargetSpec,
    candidate: Path,
    counterexamples: list[dict[str, Any]] | None,
    hit: GeneralizeHit,
) -> None:
    out_dir = RESULTS_DIR / finding_id / target.name
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "finding_id": finding_id,
        "target_repo": target.repo_url,
        "target_ref": target.ref,
        "target_file": str(candidate.relative_to(GEN_DIR / finding_id / target.name)).replace("\\", "/"),
        "halmos_outcome": hit.halmos_outcome,
        "counterexamples": counterexamples,
        "adapted_test_path": hit.adapted_test_path,
        "triage": TRIAGE_NOTE,
    }
    (out_dir / "counterexample.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def run_on_target(
    finding_id: str,
    spec: ExtractedSpec,
    original_test: str,
    target: TargetSpec,
    client: Anthropic,
) -> tuple[TargetRunStatus, list[GeneralizeHit]]:
    status = TargetRunStatus(
        target_name=target.name,
        repo_url=target.repo_url,
        ref=target.ref,
    )
    hits: list[GeneralizeHit] = []
    dest = GEN_DIR / finding_id / target.name

    try:
        clone_target(target.repo_url, dest, target.ref)
        ensure_solc(dest if dest.exists() else None)
        forge_install(dest)
    except Exception as exc:
        status.skip_reason = f"clone_or_install_failed: {exc}"
        console.print(f"  [yellow]SKIP[/yellow] {target.name} — {status.skip_reason}")
        return status, hits

    uups_files = find_uups_candidates(dest)
    status.uups_contracts_found = len(uups_files)
    if not uups_files:
        status.skip_reason = "no_uups_contracts"
        console.print(f"  [dim]SKIP[/dim] {target.name} — no UUPSUpgradeable contracts found")
        return status, hits

    for candidate in uups_files:
        rel = candidate.relative_to(dest)
        content = candidate.read_text(encoding="utf-8", errors="replace")
        adapted = adapt_test_with_claude(client, spec, original_test, candidate, content)
        if not adapted:
            continue

        status.adapted = True
        status.adapted_contract = str(rel).replace("\\", "/")

        test_root = detect_test_dir(dest)
        bugzy = test_root / "bugzy"
        bugzy.mkdir(parents=True, exist_ok=True)
        test_name = f"Gen_{target.name}_{candidate.stem}.t.sol"
        test_path = bugzy / test_name
        test_path.write_text(adapted + "\n", encoding="utf-8")

        built, _, _ = forge_build(dest)
        if not built:
            continue

        status.compiled = True
        rel_test = test_path.relative_to(dest)
        outcome, counterexamples, stdout, _ = run_halmos(
            dest, rel_test, contract_name=parse_contract_name(test_path), test_source=test_path
        )
        status.halmos_outcome = outcome
        status.halmos_completed = outcome in ("PASS", "FAIL")

        hit = GeneralizeHit(
            target_repo=target.repo_url,
            target_file=str(rel).replace("\\", "/"),
            halmos_outcome=outcome,
            counterexample=json.dumps(counterexamples)[:2000] if counterexamples else None,
            adapted_test_path=str(test_path.relative_to(ROOT)),
        )
        hits.append(hit)

        out = RESULTS_DIR / finding_id / f"{target.name}_{candidate.stem}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    **hit.model_dump(),
                    "halmos_stdout": stdout[:3000],
                    "status": TRIAGE_NOTE if outcome == "FAIL" else outcome,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        if outcome == "FAIL":
            status.potential = True
            save_counterexample(finding_id, target, candidate, counterexamples, hit)
            console.print(f"  [red]POTENTIAL[/red] {target.name}/{rel} — counterexample found")
        else:
            console.print(f"  [dim]{outcome}[/dim] {target.name}/{rel}")

        break

    if not status.adapted:
        status.skip_reason = status.skip_reason or "claude_skip_or_invalid_test"
        console.print(f"  [dim]SKIP[/dim] {target.name} — Claude could not adapt test")
    elif not status.compiled:
        status.skip_reason = status.skip_reason or "build_failed"
        console.print(f"  [dim]SKIP[/dim] {target.name} — forge build failed")
    elif not status.halmos_completed:
        status.skip_reason = status.skip_reason or f"halmos_{status.halmos_outcome}"
        console.print(f"  [dim]{status.halmos_outcome}[/dim] {target.name} — Halmos did not complete cleanly")

    return status, hits


def generalize_finding(finding_id: str, targets_path: Path, *, force: bool = False) -> GeneralizeResult:
    ensure_halmos()
    status = load_validation_status(finding_id)
    if status != "VALIDATED" and not force:
        raise ValueError(f"{finding_id} is not VALIDATED (status={status}); use --force to override")

    spec = ExtractedSpec.load(finding_id)
    original_test = test_file_path(finding_id).read_text(encoding="utf-8")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    client = Anthropic(api_key=api_key)

    targets = parse_targets_file(targets_path)
    all_hits: list[GeneralizeHit] = []
    target_statuses: list[TargetRunStatus] = []

    for target in targets:
        console.print(f"[bold]Target[/bold] {target.name} @ {target.ref}")
        run_status, hits = run_on_target(finding_id, spec, original_test, target, client)
        target_statuses.append(run_status)
        all_hits.extend(hits)

    potentials = [h for h in all_hits if h.halmos_outcome == "FAIL"]

    result = GeneralizeResult(
        finding_id=finding_id,
        targets_attempted=len(targets),
        targets_with_uups=sum(1 for s in target_statuses if s.uups_contracts_found > 0),
        targets_compiled=sum(1 for s in target_statuses if s.compiled),
        targets_halmos_completed=sum(1 for s in target_statuses if s.halmos_completed),
        potential_bugs_found=len(potentials),
        target_statuses=target_statuses,
        findings=potentials,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    save_generalize_metrics(result)
    return result


def save_generalize_metrics(result: GeneralizeResult) -> None:
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, Any] = {}
    if METRICS_PATH.exists():
        existing = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    if "runs" not in existing:
        existing = {"runs": []}
    existing["runs"] = [r for r in existing.get("runs", []) if r.get("finding_id") != result.finding_id]
    existing["runs"].append(result.model_dump())
    existing["generated_at"] = datetime.now(timezone.utc).isoformat()
    existing["latest"] = {
        "finding_id": result.finding_id,
        "targets_attempted": result.targets_attempted,
        "targets_with_uups": result.targets_with_uups,
        "targets_compiled": result.targets_compiled,
        "targets_halmos_completed": result.targets_halmos_completed,
        "potential_bugs_found": result.potential_bugs_found,
        "generated_at": result.generated_at,
    }
    METRICS_PATH.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")


def print_summary_table(result: GeneralizeResult) -> None:
    table = Table(title=f"Generalization sweep — {result.finding_id}")
    table.add_column("Repo")
    table.add_column("UUPS found")
    table.add_column("Compiled")
    table.add_column("Halmos")
    table.add_column("Status")

    for s in result.target_statuses:
        halmos = s.halmos_outcome or "—"
        if s.potential:
            row_status = "[red]POTENTIAL[/red]"
        elif s.skip_reason:
            row_status = f"skipped ({s.skip_reason})"
        elif s.halmos_completed:
            row_status = "ok"
        else:
            row_status = "—"
        table.add_row(
            s.target_name,
            str(s.uups_contracts_found),
            "yes" if s.compiled else "no",
            halmos,
            row_status,
        )
    console.print(table)


def cmd_one(finding_id: str, targets_path: Path, *, force: bool = False) -> int:
    load_dotenv(ROOT / ".env")
    console.print(f"[bold]Generalize[/bold] {finding_id}")
    try:
        result = generalize_finding(finding_id, targets_path, force=force)
    except ValueError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        return 1

    print_summary_table(result)
    console.print(
        f"\nAttempted {result.targets_attempted} | "
        f"UUPS found {result.targets_with_uups} | "
        f"Compiled {result.targets_compiled} | "
        f"Halmos completed {result.targets_halmos_completed} | "
        f"POTENTIAL hits {result.potential_bugs_found} ({TRIAGE_NOTE})"
    )
    console.print(f"[green]Wrote[/green] {METRICS_PATH}")
    return 0


def cmd_all(targets_path: Path, *, force: bool = False) -> int:
    load_dotenv(ROOT / ".env")
    ok = skip = 0
    for finding in load_all_seed_findings():
        status = load_validation_status(finding.id)
        if status != "VALIDATED" and not force:
            console.print(f"[dim]SKIP[/dim] {finding.id} ({status})")
            skip += 1
            continue
        if cmd_one(finding.id, targets_path, force=force) == 0:
            ok += 1
    console.print(f"\n[bold]Done:[/bold] {ok} generalized, {skip} skipped")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="BugMine cross-contract generalization")
    sub = parser.add_subparsers(dest="command", required=True)

    one_p = sub.add_parser("one")
    one_p.add_argument("finding_id")
    one_p.add_argument("--targets", type=Path, required=True)
    one_p.add_argument("--force", action="store_true", help="Run even if finding is not VALIDATED")

    all_p = sub.add_parser("all")
    all_p.add_argument("--targets", type=Path, required=True)
    all_p.add_argument("--force", action="store_true")

    args = parser.parse_args()
    if args.command == "one":
        sys.exit(cmd_one(args.finding_id, args.targets, force=args.force))
    sys.exit(cmd_all(args.targets, force=args.force))


if __name__ == "__main__":
    main()
