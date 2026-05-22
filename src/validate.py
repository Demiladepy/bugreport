"""
Self-validation loop: spec must FAIL on vulnerable commit, PASS on fix commit.

Usage:
  python -m src.validate one <finding_id>
  python -m src.validate all
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel
from rich.console import Console
from rich.table import Table

from .corpus import ROOT, load_all_seed_findings, load_seed_finding, test_file_path
from .verify import VERIFY_DIR, Outcome, VerifyResult, verify_one

console = Console()

ValidationStatus = Literal[
    "VALIDATED",
    "SPEC_TOO_WEAK",
    "SPEC_TOO_STRICT",
    "INCONCLUSIVE",
    "CANNOT_VALIDATE",
]

VALIDATION_DIR = ROOT / "results" / "validation"
METRICS_PATH = ROOT / "results" / "validation_metrics.json"


class ValidationRecord(BaseModel):
    finding_id: str
    status: ValidationStatus
    vulnerable_outcome: Outcome | None = None
    fix_outcome: Outcome | None = None
    vulnerable_result: VerifyResult | None = None
    fix_result: VerifyResult | None = None
    notes: str = ""
    validated_at: str


class ValidationMetrics(BaseModel):
    total_findings: int
    validated: int
    spec_too_weak: int
    spec_too_strict: int
    inconclusive: int
    cannot_validate_missing_fix: int
    validation_rate: float
    generated_at: str


def judge(vuln: Outcome | None, fix: Outcome | None) -> tuple[ValidationStatus, str]:
    inconclusive_outcomes = {"TIMEOUT", "ERROR", "BUILD_FAILED"}

    if vuln in inconclusive_outcomes or fix in inconclusive_outcomes:
        return "INCONCLUSIVE", f"vulnerable={vuln}, fix={fix}"

    if vuln == "FAIL" and fix == "PASS":
        return "VALIDATED", "Spec fails on bug and passes on fix."

    if vuln == "PASS" and fix == "PASS":
        return "SPEC_TOO_WEAK", "Spec passes on vulnerable commit — does not catch bug."

    if vuln == "FAIL" and fix == "FAIL":
        return "SPEC_TOO_STRICT", "Spec fails on fix commit — over-constrained or wrong property."

    if vuln == "PASS" and fix == "FAIL":
        return "INCONCLUSIVE", "Unexpected: passes on bug, fails on fix."

    return "INCONCLUSIVE", f"Unexpected outcomes: vulnerable={vuln}, fix={fix}"


def load_cached_verify(finding_id: str, commit_kind: str) -> VerifyResult | None:
    path = VERIFY_DIR / f"{finding_id}_{commit_kind}.json"
    if not path.exists():
        return None
    return VerifyResult.model_validate_json(path.read_text(encoding="utf-8"))


def validate_finding(finding_id: str, *, use_cached: bool = False) -> ValidationRecord:
    finding = load_seed_finding(finding_id)

    if not finding.fix_commit:
        return ValidationRecord(
            finding_id=finding_id,
            status="CANNOT_VALIDATE",
            notes="fix_commit is null — cannot run self-validation",
            validated_at=datetime.now(timezone.utc).isoformat(),
        )

    if not test_file_path(finding_id).exists():
        return ValidationRecord(
            finding_id=finding_id,
            status="INCONCLUSIVE",
            notes="No generated test — run codegen first",
            validated_at=datetime.now(timezone.utc).isoformat(),
        )

    vuln_result = load_cached_verify(finding_id, "vulnerable") if use_cached else None
    fix_result = load_cached_verify(finding_id, "fix") if use_cached else None

    if not vuln_result:
        console.print(f"  [dim]verify vulnerable...[/dim]")
        vuln_result = verify_one(finding_id, "vulnerable")
    else:
        console.print(f"  [dim]cached vulnerable: {vuln_result.halmos_outcome}[/dim]")

    if not fix_result:
        console.print(f"  [dim]verify fix...[/dim]")
        fix_result = verify_one(finding_id, "fix")
    else:
        console.print(f"  [dim]cached fix: {fix_result.halmos_outcome}[/dim]")

    status, notes = judge(vuln_result.halmos_outcome, fix_result.halmos_outcome)

    return ValidationRecord(
        finding_id=finding_id,
        status=status,
        vulnerable_outcome=vuln_result.halmos_outcome,
        fix_outcome=fix_result.halmos_outcome,
        vulnerable_result=vuln_result,
        fix_result=fix_result,
        notes=notes,
        validated_at=datetime.now(timezone.utc).isoformat(),
    )


def save_record(record: ValidationRecord) -> Path:
    VALIDATION_DIR.mkdir(parents=True, exist_ok=True)
    path = VALIDATION_DIR / f"{record.finding_id}.json"
    path.write_text(record.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path


def compute_metrics(records: list[ValidationRecord]) -> ValidationMetrics:
    validated = spec_too_weak = spec_too_strict = inconclusive = cannot_validate = 0
    for r in records:
        if r.status == "VALIDATED":
            validated += 1
        elif r.status == "SPEC_TOO_WEAK":
            spec_too_weak += 1
        elif r.status == "SPEC_TOO_STRICT":
            spec_too_strict += 1
        elif r.status == "CANNOT_VALIDATE":
            cannot_validate += 1
        else:
            inconclusive += 1

    denom = validated + spec_too_weak + spec_too_strict
    rate = round(validated / denom, 3) if denom else 0.0

    return ValidationMetrics(
        total_findings=len(records),
        validated=validated,
        spec_too_weak=spec_too_weak,
        spec_too_strict=spec_too_strict,
        inconclusive=inconclusive,
        cannot_validate_missing_fix=cannot_validate,
        validation_rate=rate,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def save_metrics(metrics: ValidationMetrics) -> None:
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(metrics.model_dump_json(indent=2) + "\n", encoding="utf-8")


def print_summary_table(records: list[ValidationRecord], metrics: ValidationMetrics) -> None:
    table = Table(title="Self-validation results")
    table.add_column("finding_id")
    table.add_column("status")
    table.add_column("vulnerable")
    table.add_column("fix")
    table.add_column("notes")

    styles = {
        "VALIDATED": "green",
        "SPEC_TOO_WEAK": "yellow",
        "SPEC_TOO_STRICT": "yellow",
        "INCONCLUSIVE": "red",
        "CANNOT_VALIDATE": "dim",
    }

    for r in records:
        style = styles.get(r.status, "white")
        table.add_row(
            r.finding_id,
            f"[{style}]{r.status}[/{style}]",
            r.vulnerable_outcome or "—",
            r.fix_outcome or "—",
            (r.notes[:50] + "…") if len(r.notes) > 50 else r.notes,
        )

    console.print(table)
    console.print(
        f"\n[bold]Validation rate:[/bold] {metrics.validation_rate:.1%} "
        f"({metrics.validated}/{metrics.validated + metrics.spec_too_weak + metrics.spec_too_strict} decidable)"
    )
    console.print(
        f"Validated={metrics.validated} | Too weak={metrics.spec_too_weak} | "
        f"Too strict={metrics.spec_too_strict} | Inconclusive={metrics.inconclusive} | "
        f"Missing fix={metrics.cannot_validate_missing_fix}"
    )


def cmd_one(finding_id: str, *, use_cached: bool = False) -> int:
    load_dotenv(ROOT / ".env")
    console.print(f"[bold]Validate[/bold] {finding_id}")
    record = validate_finding(finding_id, use_cached=use_cached)
    path = save_record(record)
    metrics = compute_metrics([record])
    style = {"VALIDATED": "green", "CANNOT_VALIDATE": "dim"}.get(record.status, "yellow")
    console.print(f"[{style}]{record.status}[/{style}] -> {path}")
    console.print(f"  {record.notes}")
    return 0 if record.status == "VALIDATED" else 1


def cmd_all(*, use_cached: bool = False) -> int:
    load_dotenv(ROOT / ".env")
    findings = [f for f in load_all_seed_findings() if f.category == "access-control"]
    records: list[ValidationRecord] = []

    for finding in findings:
        console.print(f"\n[bold]Validate[/bold] {finding.id}")
        try:
            record = validate_finding(finding.id, use_cached=use_cached)
        except Exception as exc:
            console.print(f"[red]ERROR[/red] {finding.id}: {exc}")
            record = ValidationRecord(
                finding_id=finding.id,
                status="INCONCLUSIVE",
                notes=str(exc),
                validated_at=datetime.now(timezone.utc).isoformat(),
            )
        save_record(record)
        records.append(record)
        console.print(f"  -> {record.status}: {record.notes}")

    metrics = compute_metrics(records)
    save_metrics(metrics)
    print_summary_table(records, metrics)
    console.print(f"\n[green]Wrote[/green] {METRICS_PATH}")

    try:
        from .benchmark import cmd_report

        cmd_report()
        console.print("[green]Wrote[/green] results/benchmark_run.json")
    except Exception as exc:
        console.print(f"[yellow]benchmark report skipped:[/yellow] {exc}")

    return 0 if metrics.validated >= 1 else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="BugMine self-validation")
    sub = parser.add_subparsers(dest="command", required=True)
    one_p = sub.add_parser("one")
    one_p.add_argument("finding_id")
    one_p.add_argument("--use-cached", action="store_true")

    all_p = sub.add_parser("all")
    all_p.add_argument("--use-cached", action="store_true")
    args = parser.parse_args()
    if args.command == "one":
        sys.exit(cmd_one(args.finding_id, use_cached=args.use_cached))
    sys.exit(cmd_all(use_cached=args.use_cached))


if __name__ == "__main__":
    main()
