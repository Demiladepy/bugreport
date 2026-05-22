"""Shared helpers for loading corpus findings."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
SEED_PATH = ROOT / "data" / "findings_seed.jsonl"


class SeedFinding(BaseModel):
    id: str
    title: str
    source_url: str
    category: str
    severity: str
    repo_url: str | None = None
    vulnerable_commit: str | None = None
    fix_commit: str | None = None
    affected_file: str | None = None
    bug_spec: str | None = None
    raw_markdown: str = ""
    synthetic_fix: bool = False
    synthetic_fix_note: str | None = None


def load_seed_finding(finding_id: str, path: Path = SEED_PATH) -> SeedFinding:
    if not path.exists():
        raise FileNotFoundError(f"Seed file not found: {path}")
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        if data.get("id") == finding_id:
            return SeedFinding.model_validate(data)
    raise KeyError(f"Finding not found: {finding_id}")


def load_all_seed_findings(path: Path = SEED_PATH) -> list[SeedFinding]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    out: list[SeedFinding] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(SeedFinding.model_validate(json.loads(line)))
    return out


def test_contract_name(finding_id: str) -> str:
    safe = finding_id.replace("-", "_")
    return f"Test{safe}"


def test_dir(finding_id: str, root: Path = ROOT) -> Path:
    return root / "data" / "tests" / finding_id


def test_file_path(finding_id: str, root: Path = ROOT) -> Path:
    return test_dir(finding_id, root) / f"{test_contract_name(finding_id)}.t.sol"
