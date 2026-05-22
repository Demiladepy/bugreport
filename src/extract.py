"""
LLM extraction: audit finding → formal spec in data/specs/.

Usage:
  python -m src.extract one <finding_id>
  python -m src.extract all
  python -m src.extract show <finding_id>
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
from typing import Any, Literal

from anthropic import Anthropic
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

ROOT = Path(__file__).resolve().parents[1]
SEED_PATH = ROOT / "data" / "findings_seed.jsonl"
SPECS_DIR = ROOT / "data" / "specs"
METRICS_PATH = ROOT / "results" / "extraction_metrics.json"

DEFAULT_MODEL = "claude-opus-4-5"
MAX_TOKENS = 2000

console = Console()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class ViolatedInvariant(BaseModel):
    precondition: str
    should_revert: bool
    expected_behavior: str


SpecType = Literal["access_control", "state_machine", "init_pattern", "other"]
Confidence = Literal["high", "medium", "low"]


class ExtractedSpec(BaseModel):
    finding_id: str
    spec_natural_language: str
    spec_type: SpecType
    function_signature: str
    violated_invariant: ViolatedInvariant
    halmos_property_sketch: str
    affected_function_lines: list[int] | None = None
    extraction_confidence: Confidence
    extraction_reasoning: str
    model: str
    extracted_at: str

    def save(self, root: Path = ROOT) -> Path:
        path = root / "data" / "specs" / f"{self.finding_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return path

    @classmethod
    def load(cls, finding_id: str, root: Path = ROOT) -> ExtractedSpec:
        path = root / "data" / "specs" / f"{finding_id}.json"
        return cls.model_validate_json(path.read_text(encoding="utf-8"))


class FindingRecord(BaseModel):
    id: str
    title: str
    category: str
    affected_file: str | None = None
    bug_spec: str | None = None
    raw_markdown: str = ""


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a formal-methods-aware smart contract security auditor.

Your output will be turned into a Halmos symbolic execution property test in Solidity.
Extract ONLY the core access-control or state-machine invariant violated by this finding.

IGNORE: gas optimization, code style, oracle/data feed issues, documentation nits,
centralization advice without a concrete callable function, and generic best practices.

Requirements:
- spec_natural_language MUST be expressible as: "function F MUST/MUST NOT do X when condition C"
- function_signature MUST be a single target function, e.g. "upgradeTo(address)" or "vote_for_gauge_weights(address,uint256)"
- Focus on the one function whose behavior is wrong under the stated precondition
- halmos_property_sketch: pseudo-Solidity sketch using Halmos-style check_* function that would FAIL on the bug and PASS on the fix
- affected_function_lines: best guess [startLine, endLine] from the report, or null if unknown
- extraction_confidence: high if the invariant is unambiguous from the report; medium if inferred; low if ambiguous or insufficient detail
- extraction_reasoning: brief justification for confidence level

Respond ONLY with valid JSON matching this exact schema (no markdown fences, no prose):
{
  "finding_id": string,
  "spec_natural_language": string,
  "spec_type": "access_control" | "state_machine" | "init_pattern" | "other",
  "function_signature": string,
  "violated_invariant": {
    "precondition": string,
    "should_revert": boolean,
    "expected_behavior": string
  },
  "halmos_property_sketch": string,
  "affected_function_lines": [int, int] | null,
  "extraction_confidence": "high" | "medium" | "low",
  "extraction_reasoning": string
}"""

RETRY_SUFFIX = (
    "\n\nIMPORTANT: Your previous response was not valid JSON. "
    "Respond ONLY with a single JSON object. No markdown fences. No commentary."
)


# ---------------------------------------------------------------------------
# Seed loading
# ---------------------------------------------------------------------------


def load_all_findings(path: Path = SEED_PATH) -> list[FindingRecord]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    records: list[FindingRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        records.append(
            FindingRecord(
                id=data["id"],
                title=data.get("title", ""),
                category=data.get("category", "other"),
                affected_file=data.get("affected_file"),
                bug_spec=data.get("bug_spec"),
                raw_markdown=data.get("raw_markdown", ""),
            )
        )
    return records


def load_finding(finding_id: str, path: Path = SEED_PATH) -> FindingRecord:
    for record in load_all_findings(path):
        if record.id == finding_id:
            return record
    raise KeyError(f"Finding not found in seed file: {finding_id}")


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def build_user_message(finding: FindingRecord) -> str:
    parts = [
        f"Finding ID: {finding.id}",
        f"Title: {finding.title}",
        f"Category hint: {finding.category}",
        f"Affected file: {finding.affected_file or 'unknown'}",
    ]
    if finding.bug_spec:
        parts.append(
            "Human-provided hint (verify against the markdown — do NOT blindly trust if inconsistent):\n"
            f"{finding.bug_spec}"
        )
    parts.append("---\nAudit finding markdown:\n---")
    parts.append(finding.raw_markdown or "(empty)")
    return "\n\n".join(parts)


def strip_json_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def parse_spec_response(
    raw: str,
    finding_id: str,
    model: str,
    *,
    parse_error: str | None = None,
) -> ExtractedSpec:
    cleaned = strip_json_fences(raw)
    data = json.loads(cleaned)
    data["finding_id"] = finding_id
    data["model"] = model
    data["extracted_at"] = datetime.now(timezone.utc).isoformat()
    return ExtractedSpec.model_validate(data)


def fallback_spec(
    finding_id: str,
    model: str,
    reason: str,
    raw_response: str = "",
) -> ExtractedSpec:
    return ExtractedSpec(
        finding_id=finding_id,
        spec_natural_language="EXTRACTION FAILED — manual review required",
        spec_type="other",
        function_signature="unknown()",
        violated_invariant=ViolatedInvariant(
            precondition="unknown",
            should_revert=True,
            expected_behavior="unknown",
        ),
        halmos_property_sketch="// extraction failed",
        affected_function_lines=None,
        extraction_confidence="low",
        extraction_reasoning=f"{reason}. Raw response excerpt: {raw_response[:500]}",
        model=model,
        extracted_at=datetime.now(timezone.utc).isoformat(),
    )


def call_claude(client: Anthropic, user_message: str, *, strict: bool = False) -> str:
    content = user_message + (RETRY_SUFFIX if strict else "")
    response = client.messages.create(
        model=DEFAULT_MODEL,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": content}],
    )
    return response.content[0].text


def extract_one(
    finding: FindingRecord,
    *,
    client: Anthropic | None = None,
    model: str = DEFAULT_MODEL,
) -> tuple[ExtractedSpec, float, list[str]]:
    """Extract spec for one finding. Returns (spec, elapsed_ms, warnings)."""
    warnings: list[str] = []

    if not finding.raw_markdown or not finding.raw_markdown.strip():
        warnings.append(f"{finding.id}: raw_markdown missing — skipped")
        raise ValueError("raw_markdown missing")

    if client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set in environment")
        client = Anthropic(api_key=api_key)

    user_message = build_user_message(finding)
    t0 = time.perf_counter()

    raw = call_claude(client, user_message, strict=False)
    try:
        spec = parse_spec_response(raw, finding.id, model)
    except (json.JSONDecodeError, ValidationError) as exc:
        warnings.append(f"{finding.id}: first parse failed ({exc}) — retrying")
        raw_retry = call_claude(client, user_message, strict=True)
        try:
            spec = parse_spec_response(raw_retry, finding.id, model)
        except (json.JSONDecodeError, ValidationError) as exc2:
            warnings.append(f"{finding.id}: retry parse failed ({exc2}) — saving low-confidence fallback")
            spec = fallback_spec(finding.id, model, str(exc2), raw_retry)

    elapsed_ms = (time.perf_counter() - t0) * 1000

    if spec.extraction_confidence == "low":
        warnings.append(f"{finding.id}: extraction_confidence=LOW — review required")

    return spec, elapsed_ms, warnings


def is_successful_extraction(spec: ExtractedSpec) -> bool:
    if spec.extraction_confidence == "low" and spec.spec_natural_language.startswith("EXTRACTION FAILED"):
        return False
    required = [
        spec.spec_natural_language,
        spec.function_signature,
        spec.violated_invariant.precondition,
        spec.halmos_property_sketch,
    ]
    return all(v and v not in ("unknown", "unknown()") for v in required)


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------


def print_spec_summary(spec: ExtractedSpec) -> None:
    conf_style = {
        "high": "[green]high[/green]",
        "medium": "[yellow]medium[/yellow]",
        "low": "[red]low[/red]",
    }[spec.extraction_confidence]

    table = Table(title=f"Extracted spec — {spec.finding_id}", show_header=True)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("spec_natural_language", spec.spec_natural_language)
    table.add_row("spec_type", spec.spec_type)
    table.add_row("function_signature", spec.function_signature)
    table.add_row("precondition", spec.violated_invariant.precondition)
    table.add_row("should_revert", str(spec.violated_invariant.should_revert))
    table.add_row("expected_behavior", spec.violated_invariant.expected_behavior)
    table.add_row("confidence", conf_style)
    table.add_row("reasoning", spec.extraction_reasoning[:120] + ("…" if len(spec.extraction_reasoning) > 120 else ""))
    console.print(Panel(table))


def print_spec_full(spec: ExtractedSpec) -> None:
    console.print_json(spec.model_dump_json())


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def write_extraction_metrics(results: list[tuple[FindingRecord, ExtractedSpec | None, float, list[str]]]) -> None:
    successful = 0
    failed = 0
    by_confidence: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    by_category: dict[str, int] = {}
    times: list[float] = []

    for finding, spec, elapsed_ms, _warnings in results:
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
        if spec is None:
            failed += 1
            continue
        times.append(elapsed_ms)
        by_confidence[spec.extraction_confidence] = by_confidence.get(spec.extraction_confidence, 0) + 1
        if is_successful_extraction(spec):
            successful += 1
        else:
            failed += 1

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(results),
        "extraction_successful": successful,
        "extraction_failed": failed,
        "by_confidence": by_confidence,
        "by_category": by_category,
        "avg_response_time_ms": round(sum(times) / len(times), 1) if times else 0.0,
    }
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    console.print(f"\n[green]Wrote[/green] {METRICS_PATH}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_one(finding_id: str) -> int:
    load_dotenv(ROOT / ".env")
    finding = load_finding(finding_id)
    spec, elapsed_ms, warnings = extract_one(finding)
    path = spec.save()
    print_spec_summary(spec)
    console.print(f"Saved -> {path}  ({elapsed_ms:.0f} ms)")
    for w in warnings:
        console.print(f"[yellow]WARNING:[/yellow] {w}")
    console.print("\n[bold]Full JSON:[/bold]")
    console.print_json(spec.model_dump_json())
    return 0


def cmd_all() -> int:
    load_dotenv(ROOT / ".env")
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]ANTHROPIC_API_KEY not set[/red]")
        return 1
    client = Anthropic(api_key=api_key)

    findings = load_all_findings()
    if not findings:
        console.print("[yellow]No findings in seed file[/yellow]")
        return 1

    results: list[tuple[FindingRecord, ExtractedSpec | None, float, list[str]]] = []
    ok = fail = 0

    for finding in findings:
        console.print(f"\n[bold]Extracting[/bold] {finding.id} …")
        if not finding.raw_markdown or not finding.raw_markdown.strip():
            console.print(f"[yellow]WARNING:[/yellow] {finding.id}: raw_markdown missing — skipped")
            results.append((finding, None, 0.0, ["raw_markdown missing"]))
            fail += 1
            continue
        try:
            spec, elapsed_ms, warnings = extract_one(finding, client=client)
            spec.save()
            print_spec_summary(spec)
            for w in warnings:
                console.print(f"[yellow]WARNING:[/yellow] {w}")
            results.append((finding, spec, elapsed_ms, warnings))
            if is_successful_extraction(spec):
                ok += 1
            else:
                fail += 1
        except Exception as exc:
            console.print(f"[red]FAILED[/red] {finding.id}: {exc}")
            results.append((finding, None, 0.0, [str(exc)]))
            fail += 1

    write_extraction_metrics(results)
    console.print(f"\n[bold]Done:[/bold] {ok} successful, {fail} failed / {len(findings)} total")
    return 0 if fail == 0 else 1


def cmd_show(finding_id: str) -> int:
    path = SPECS_DIR / f"{finding_id}.json"
    if not path.exists():
        console.print(f"[red]No extraction found:[/red] {path}")
        return 1
    spec = ExtractedSpec.load(finding_id)
    print_spec_full(spec)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="BugMine spec extraction via Claude")
    sub = parser.add_subparsers(dest="command", required=True)

    one_p = sub.add_parser("one", help="Extract a single finding")
    one_p.add_argument("finding_id")

    sub.add_parser("all", help="Extract all findings in seed file")

    show_p = sub.add_parser("show", help="Show existing extraction")
    show_p.add_argument("finding_id")

    args = parser.parse_args()

    if args.command == "one":
        sys.exit(cmd_one(args.finding_id))
    elif args.command == "all":
        sys.exit(cmd_all())
    elif args.command == "show":
        sys.exit(cmd_show(args.finding_id))


if __name__ == "__main__":
    main()
