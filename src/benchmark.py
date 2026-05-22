"""
Aggregate benchmark metrics across the full pipeline run.

Usage:
  python -m src.benchmark report
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .corpus import ROOT, SEED_PATH, load_all_seed_findings, test_file_path
from .extract import METRICS_PATH as EXTRACT_METRICS_PATH, SPECS_DIR, ExtractedSpec, is_successful_extraction
from .validate import VALIDATION_DIR, ValidationRecord, compute_metrics
from .verify import VERIFY_DIR, VerifyResult

BENCHMARK_PATH = ROOT / "results" / "benchmark_run.json"
TABLE_PATH = ROOT / "results" / "per_finding_table.md"
ACCESS_CONTROL_ONLY = True
INGESTION_FIELDS = ("repo_url", "vulnerable_commit", "fix_commit", "affected_file")


def corpus_findings():
    findings = load_all_seed_findings()
    if ACCESS_CONTROL_ONLY:
        return [f for f in findings if f.category == "access-control"]
    return findings


def load_verify(finding_id: str, kind: str) -> VerifyResult | None:
    path = VERIFY_DIR / f"{finding_id}_{kind}.json"
    if not path.exists():
        return None
    return VerifyResult.model_validate_json(path.read_text(encoding="utf-8"))


def load_validation(finding_id: str) -> ValidationRecord | None:
    path = VALIDATION_DIR / f"{finding_id}.json"
    if not path.exists():
        return None
    return ValidationRecord.model_validate_json(path.read_text(encoding="utf-8"))


def ingestion_block(findings) -> dict[str, Any]:
    n = len(findings)
    per_field: dict[str, float] = {}
    for field in INGESTION_FIELDS:
        present = sum(1 for f in findings if getattr(f, field))
        per_field[field] = round(present / n, 3) if n else 0.0
    all_four = sum(
        1 for f in findings
        if all(getattr(f, field) for field in INGESTION_FIELDS)
    )
    return {
        "all_4_fields_resolved": all_four,
        "missing_fix_commit": sum(1 for f in findings if not f.fix_commit),
        "missing_vulnerable_commit": sum(1 for f in findings if not f.vulnerable_commit),
        "auto_resolve_rate_per_field": per_field,
    }


def extraction_block(findings) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    if EXTRACT_METRICS_PATH.exists():
        metrics = json.loads(EXTRACT_METRICS_PATH.read_text(encoding="utf-8"))
    success = 0
    failed_invalid = 0
    by_confidence: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        spec_path = SPECS_DIR / f"{finding.id}.json"
        if not spec_path.exists():
            failed_invalid += 1
            continue
        try:
            spec = ExtractedSpec.load(finding.id)
            by_confidence[spec.extraction_confidence] = by_confidence.get(spec.extraction_confidence, 0) + 1
            if is_successful_extraction(spec):
                success += 1
            else:
                failed_invalid += 1
        except Exception:
            failed_invalid += 1
    if metrics.get("by_confidence"):
        by_confidence = metrics["by_confidence"]
    return {
        "attempted": len(findings),
        "success": success,
        "failed_invalid_json": failed_invalid,
        "by_confidence": by_confidence,
    }


def codegen_block(findings) -> dict[str, Any]:
    codegen_metrics = ROOT / "results" / "codegen_metrics.json"
    attempted = sum(1 for f in findings if (SPECS_DIR / f"{f.id}.json").exists())
    success = sum(1 for f in findings if test_file_path(f.id).exists())
    failed = max(0, attempted - success)
    if codegen_metrics.exists():
        data = json.loads(codegen_metrics.read_text(encoding="utf-8"))
        success = data.get("success", success)
        failed = data.get("failed", failed)
        attempted = data.get("total", attempted) - data.get("skipped_curated", 0)
    return {
        "attempted": attempted,
        "success": success,
        "failed_invalid_solidity": failed,
    }


def verify_block(findings, kind: str) -> dict[str, Any]:
    attempted = 0
    fail_expected = pass_expected = 0
    pass_unexpected = fail_unexpected = 0
    build_failed = halmos_timeout = halmos_error = 0
    no_fix = 0

    for finding in findings:
        if kind == "fix" and not finding.fix_commit:
            no_fix += 1
            continue
        if not test_file_path(finding.id).exists():
            continue
        result = load_verify(finding.id, kind)
        if not result:
            continue
        attempted += 1
        outcome = result.halmos_outcome
        if kind == "vulnerable":
            if outcome == "FAIL":
                fail_expected += 1
            elif outcome == "PASS":
                pass_unexpected += 1
            elif outcome == "BUILD_FAILED":
                build_failed += 1
            elif outcome == "TIMEOUT":
                halmos_timeout += 1
            elif outcome == "ERROR":
                halmos_error += 1
        else:
            if outcome == "PASS":
                pass_expected += 1
            elif outcome == "FAIL":
                fail_unexpected += 1
            elif outcome == "BUILD_FAILED":
                build_failed += 1
            elif outcome == "TIMEOUT":
                halmos_timeout += 1

    if kind == "vulnerable":
        return {
            "attempted": attempted,
            "fail_as_expected": fail_expected,
            "pass_unexpected": pass_unexpected,
            "build_failed": build_failed,
            "halmos_timeout": halmos_timeout,
            "halmos_error": halmos_error,
        }
    return {
        "attempted": attempted,
        "pass_as_expected": pass_expected,
        "fail_unexpected": fail_unexpected,
        "build_failed": build_failed,
        "halmos_timeout": halmos_timeout,
        "no_fix_commit": no_fix,
    }


def validation_block(findings) -> dict[str, Any]:
    records: list[ValidationRecord] = []
    for finding in findings:
        val = load_validation(finding.id)
        if val:
            records.append(val)
        elif not finding.fix_commit:
            records.append(
                ValidationRecord(
                    finding_id=finding.id,
                    status="CANNOT_VALIDATE",
                    notes="fix_commit is null",
                    validated_at=datetime.now(timezone.utc).isoformat(),
                )
            )
    metrics = compute_metrics(records) if records else None
    validated = metrics.validated if metrics else 0
    too_weak = metrics.spec_too_weak if metrics else 0
    too_strict = metrics.spec_too_strict if metrics else 0
    inconclusive = metrics.inconclusive if metrics else 0
    cannot_no_fix = metrics.cannot_validate_missing_fix if metrics else sum(
        1 for f in findings if not f.fix_commit
    )
    decidable = validated + too_weak + too_strict
    return {
        "validated": validated,
        "spec_too_weak": too_weak,
        "spec_too_strict": too_strict,
        "inconclusive": inconclusive,
        "cannot_validate_no_fix": cannot_no_fix,
        "_decidable": decidable,
    }


def per_finding_rows(findings) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in findings:
        spec_ok = False
        spec_path = SPECS_DIR / f"{finding.id}.json"
        if spec_path.exists():
            try:
                spec_ok = is_successful_extraction(ExtractedSpec.load(finding.id))
            except Exception:
                spec_ok = False
        vuln = load_verify(finding.id, "vulnerable")
        fix = load_verify(finding.id, "fix")
        val = load_validation(finding.id)
        rows.append({
            "id": finding.id,
            "title": finding.title[:70],
            "ingestion": "complete" if all(getattr(finding, f) for f in INGESTION_FIELDS) else "partial",
            "extract": "ok" if spec_ok else "fail",
            "codegen": "ok" if test_file_path(finding.id).exists() else "fail",
            "vulnerable": vuln.halmos_outcome if vuln else "—",
            "fix": fix.halmos_outcome if fix else ("no_fix" if not finding.fix_commit else "—"),
            "validation": val.status if val else ("CANNOT_VALIDATE" if not finding.fix_commit else "NOT_RUN"),
        })
    return rows


def write_per_finding_table(rows: list[dict[str, Any]]) -> None:
    header = "| ID | Title | Ingest | Extract | Codegen | Vuln verify | Fix verify | Validation |"
    sep = "|---|---|---|---|---|---|---|---|"
    lines = ["# Per-finding pipeline outcomes", "", header, sep]
    for row in rows:
        lines.append(
            f"| `{row['id']}` | {row['title']} | {row['ingestion']} | {row['extract']} | "
            f"{row['codegen']} | {row['vulnerable']} | {row['fix']} | {row['validation']} |"
        )
    validated = [r["id"] for r in rows if r["validation"] == "VALIDATED"]
    if validated:
        lines.extend(["", "## Validated findings", ""])
        for fid in validated:
            lines.append(f"- `{fid}`")
    TABLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    TABLE_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_report() -> dict[str, Any]:
    findings = corpus_findings()
    n = len(findings)
    validation = validation_block(findings)
    decidable = validation.pop("_decidable", 0)
    validated = validation["validated"]

    report = {
        "corpus_size": n,
        "ingestion": ingestion_block(findings),
        "extraction": extraction_block(findings),
        "codegen": codegen_block(findings),
        "verify_vulnerable": verify_block(findings, "vulnerable"),
        "verify_fix": verify_block(findings, "fix"),
        "validation": validation,
        "validation_rate_on_decidable": round(validated / decidable, 3) if decidable else 0.0,
        "end_to_end_completion_rate": round(validated / n, 3) if n else 0.0,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return report


def cmd_report() -> int:
    findings = corpus_findings()
    report = build_report()
    rows = per_finding_rows(findings)
    BENCHMARK_PATH.parent.mkdir(parents=True, exist_ok=True)
    BENCHMARK_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    write_per_finding_table(rows)
    print(f"Wrote {BENCHMARK_PATH}")
    print(f"Wrote {TABLE_PATH}")
    print(
        f"Validated: {report['validation']['validated']} / "
        f"{report['corpus_size']} "
        f"({report['end_to_end_completion_rate']:.1%} end-to-end)"
    )
    return 0


def main() -> None:
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "report":
        sys.exit(cmd_report())
    print("Usage: python -m src.benchmark report")
    sys.exit(1)


if __name__ == "__main__":
    main()
