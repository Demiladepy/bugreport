"""Discover Code4rena access-control H findings via GitHub search."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

SKIP_CONTESTS = {"2023-06-llama", "2024-07-basin", "2025-05-blackhole", "2024-03-neobase"}
EXISTING_IDS: set[str] = set()

QUERIES = [
    'org:code-423n4 "Assessed type" "Access Control" in:body is:issue',
    "org:code-423n4 onlyOwner in:body is:issue",
    "org:code-423n4 unauthorized in:body is:issue",
    "org:code-423n4 onlyRole in:body is:issue",
    "org:code-423n4 missing modifier in:body is:issue",
    "org:code-423n4 access control in:body is:issue",
    "org:code-423n4 _authorizeUpgrade in:body is:issue",
    "org:code-423n4 onlyAdmin in:body is:issue",
    "org:code-423n4 msg.sender in:body is:issue label:H-01",
]


def search(query: str, token: str) -> list[dict]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    resp = requests.get(
        "https://api.github.com/search/issues",
        params={"q": query, "per_page": 100, "sort": "created", "order": "desc"},
        headers=headers,
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json().get("items", [])


def has_function_reference(body: str) -> bool:
    return bool(
        re.search(r"function\s+[A-Za-z_]\w*\s*\(", body)
        or re.search(r"::[A-Za-z_]\w*\s*\(", body)
        or re.search(r"`[A-Za-z_]\w*\(\)", body)
    )


def is_high_or_critical(title: str, body: str, labels: list[str]) -> bool:
    text = f"{title}\n{body}\n" + " ".join(labels)
    if re.search(r"\bcritical\b", text, re.I):
        return True
    if re.search(r"\bhigh\b", text, re.I):
        return True
    if any(re.match(r"^H-\d+$", lbl, re.I) for lbl in labels):
        return True
    if re.search(r"\[H-\d+\]", title, re.I):
        return True
    return False


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN required", file=sys.stderr)
        sys.exit(1)

    seed_path = ROOT / "data" / "findings_seed.jsonl"
    if seed_path.exists():
        import json

        for line in seed_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                EXISTING_IDS.add(json.loads(line)["id"])

    seen_urls: set[str] = set()
    candidates: list[tuple[str, str]] = []

    for query in QUERIES:
        try:
            items = search(query, token)
        except Exception as exc:
            print(f"# query failed: {query}: {exc}", file=sys.stderr)
            continue
        for item in items:
            url = item["html_url"]
            if url in seen_urls:
                continue
            repo = item["repository_url"].split("/")[-1]
            if not repo.endswith("-findings"):
                continue
            contest = repo[: -len("-findings")]
            if contest in SKIP_CONTESTS:
                continue
            title = item.get("title") or ""
            body = item.get("body") or ""
            labels = [lbl["name"] for lbl in item.get("labels", [])]
            if not is_high_or_critical(title, body, labels):
                continue
            if not has_function_reference(body):
                continue
            if not re.search(r"access\s*control|onlyowner|onlyrole|unauthorized|missing modifier|privilege", body + title, re.I):
                continue
            seen_urls.add(url)
            candidates.append((url, title))

    print(f"# Found {len(candidates)} candidates")
    for url, title in candidates[:30]:
        print(f"{url}\t{title[:100]}")


if __name__ == "__main__":
    main()
