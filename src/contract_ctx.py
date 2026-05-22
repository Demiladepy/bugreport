"""Fetch target contract context for real-contract test codegen."""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse

from .fetch import GitHubClient, parse_repo_url

ROOT = Path(__file__).resolve().parents[1]
CURATED_MANIFEST = ROOT / "data" / "tests" / "curated.txt"


def is_curated(finding_id: str) -> bool:
    if not CURATED_MANIFEST.exists():
        return False
    ids = {line.strip() for line in CURATED_MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip()}
    return finding_id in ids


def contract_name_from_path(affected_file: str | None) -> str | None:
    if not affected_file:
        return None
    return Path(affected_file).stem


def import_path(affected_file: str | None) -> str | None:
    if not affected_file:
        return None
    return affected_file.lstrip("/").replace("\\", "/")


def fetch_source(repo_url: str | None, affected_file: str | None, ref: str | None) -> tuple[str | None, str | None]:
    if not repo_url or not affected_file or not ref:
        return None, None
    token = os.environ.get("GITHUB_TOKEN")
    client = GitHubClient(token)
    owner, repo = parse_repo_url(repo_url)
    path = affected_file.lstrip("/")
    text = client.raw_file(owner, repo, path, ref)
    if not text:
        return None, contract_name_from_path(affected_file)
    return text, contract_name_from_path(affected_file)


def detect_pragma(source: str | None) -> str:
    if not source:
        return "^0.8.20"
    m = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    return m.group(1).strip() if m else "^0.8.20"


def summarize_source(source: str, *, limit: int = 10000) -> str:
    if len(source) <= limit:
        return source
    return source[: limit // 2] + "\n// ... truncated ...\n" + source[-limit // 2 :]
