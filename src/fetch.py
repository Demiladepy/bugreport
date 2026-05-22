"""
Corpus ingestion CLI — build data/findings_seed.jsonl one finding at a time.

Usage:
  python -m src.fetch add <github_url>
  python -m src.fetch list
  python -m src.fetch validate
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import requests
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

ROOT = Path(__file__).resolve().parents[1]
SEED_PATH = ROOT / "data" / "findings_seed.jsonl"
GITHUB_API = "https://api.github.com"

console = Console()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class AutoResolved(BaseModel):
    repo_url: bool = False
    vulnerable_commit: bool = False
    fix_commit: bool = False
    affected_file: bool = False


class FindingSeed(BaseModel):
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
    raw_markdown: str
    synthetic_fix: bool = False
    synthetic_fix_note: str | None = None
    auto_resolved: AutoResolved = Field(default_factory=AutoResolved)
    ingested_at: str

    @field_validator("category")
    @classmethod
    def normalize_category(cls, v: str) -> str:
        return v.strip().lower().replace("_", "-")

    @field_validator("severity")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        return v.strip().lower()

    def completeness(self) -> tuple[int, int]:
        flags = self.auto_resolved
        resolved = sum([flags.repo_url, flags.vulnerable_commit, flags.fix_commit, flags.affected_file])
        return resolved, 4

    def required_complete(self) -> bool:
        return all([self.repo_url, self.vulnerable_commit, self.fix_commit, self.affected_file])


# ---------------------------------------------------------------------------
# GitHub client
# ---------------------------------------------------------------------------


class GitHubClient:
    def __init__(self, token: str | None = None) -> None:
        self.session = requests.Session()
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "bugmine-fetch",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.session.headers.update(headers)

    def get(self, path: str, *, params: dict | None = None) -> Any:
        url = path if path.startswith("http") else f"{GITHUB_API}{path}"
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                resp = self.session.get(url, params=params, timeout=60)
                if resp.status_code == 403 and "rate limit" in resp.text.lower():
                    raise RuntimeError("GitHub API rate limit exceeded. Set GITHUB_TOKEN in .env")
                if resp.status_code == 404:
                    return None
                if resp.status_code == 422:
                    return None
                resp.raise_for_status()
                if resp.content:
                    return resp.json()
                return None
            except requests.RequestException as exc:
                last_exc = exc
                time.sleep(1 + attempt)
        if last_exc:
            raise last_exc
        return None

    def head(self, url: str) -> int:
        resp = self.session.head(url, timeout=30, allow_redirects=True)
        return resp.status_code

    def raw_file(self, owner: str, repo: str, path: str, ref: str = "main") -> str | None:
        for branch in (ref, "master"):
            url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
            resp = self.session.get(url, timeout=60)
            if resp.status_code == 200:
                return resp.text
        data = self.get(f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref})
        if not data or not isinstance(data, dict):
            return None
        import base64

        content = data.get("content")
        if not content:
            return None
        return base64.b64decode(content).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------


class ParsedGitHubURL(BaseModel):
    owner: str
    repo: str
    kind: str  # issue | blob
    issue_number: int | None = None
    blob_path: str | None = None
    blob_ref: str = "main"


def parse_github_url(url: str) -> ParsedGitHubURL:
    parsed = urlparse(url)
    if parsed.netloc not in ("github.com", "www.github.com"):
        raise ValueError(f"Not a GitHub URL: {url}")

    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 3:
        raise ValueError(f"Unrecognized GitHub URL shape: {url}")

    owner, repo = parts[0], parts[1]

    if len(parts) >= 4 and parts[2] == "issues" and parts[3].isdigit():
        return ParsedGitHubURL(
            owner=owner,
            repo=repo,
            kind="issue",
            issue_number=int(parts[3]),
        )

    if len(parts) >= 5 and parts[2] == "blob":
        ref = parts[3]
        blob_path = unquote("/".join(parts[4:]))
        return ParsedGitHubURL(
            owner=owner,
            repo=repo,
            kind="blob",
            blob_path=blob_path,
            blob_ref=ref,
        )

    raise ValueError(f"Unsupported GitHub URL shape: {url}")


def contest_from_repo(repo: str) -> str:
    if repo.endswith("-findings"):
        return repo[: -len("-findings")]
    return repo


# ---------------------------------------------------------------------------
# Extraction heuristics
# ---------------------------------------------------------------------------

SEVERITY_PATTERNS = [
    (re.compile(r"\b(critical)\b", re.I), "critical"),
    (re.compile(r"\b(high)\b", re.I), "high"),
    (re.compile(r"\b(medium|med)\b", re.I), "medium"),
    (re.compile(r"\[(H-\d+)\]", re.I), "high"),
    (re.compile(r"\[(M-\d+)\]", re.I), "medium"),
    (re.compile(r"\b3\s*\(high\s*risk\)\b", re.I), "high"),
]

CATEGORY_HINTS = {
    "access-control": re.compile(
        r"access\s*control|only\s+\w+\s+can|unauthorized|missing\s+modifier|"
        r"onlyowner|onlyrole|privilege|permission",
        re.I,
    ),
    "state-machine": re.compile(
        r"state\s*machine|wrong\s+state|should\s+not\s+be\s+callable|"
        r"when\s+paused|invalid\s+state",
        re.I,
    ),
}

FILE_PATH_RE = re.compile(
    r"(?:^|[\s`'\"(])"
    r"((?:src|contracts|test|lib)/[\w./-]+\.sol)"
    r"(?:[#:\s)]|$)",
    re.MULTILINE,
)

GITHUB_BLOB_RE = re.compile(
    r"github\.com/([^/\s]+)/([^/\s]+)/blob/([0-9a-f]{7,40}|[^/\s]+)/([\w./-]+\.sol)",
    re.I,
)

COMMIT_SHA_RE = re.compile(r"\b([0-9a-f]{40})\b", re.I)
SHORT_COMMIT_IN_URL_RE = re.compile(r"/commit/([0-9a-f]{7,40})", re.I)
REPO_URL_RE = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")
NOTION_HEX_RE = re.compile(r"notion\.site/[A-Za-z0-9-]+-([0-9a-f]{32})", re.I)


def extract_severity(title: str, body: str, labels: list[str] | None = None) -> str:
    text = f"{title}\n{body}"
    if labels:
        text += "\n" + " ".join(labels)
    for pattern, severity in SEVERITY_PATTERNS:
        if pattern.search(text):
            return severity
    return "high"


def extract_finding_id(contest: str, title: str, labels: list[str] | None = None) -> str:
    if labels:
        for label in labels:
            m = re.match(r"^(H|M|L)-(\d+)$", label, re.I)
            if m:
                return f"{contest}-{m.group(0).upper()}"
    m = re.search(r"\[(H|M|L)-(\d+)\]", title, re.I)
    if m:
        return f"{contest}-{m.group(1).upper()}-{m.group(2)}"
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40]
    return f"{contest}-{slug}"


def clean_title(title: str) -> str:
    return re.sub(r"^\[(H|M|L)-\d+\]\s*", "", title, flags=re.I).strip()


def guess_category(title: str, body: str) -> str:
    text = f"{title}\n{body}"
    for category, pattern in CATEGORY_HINTS.items():
        if pattern.search(text):
            return category
    if re.search(r"assessed type\s*\n+\s*access control", text, re.I):
        return "access-control"
    return "other"


def extract_affected_file(title: str, body: str) -> str | None:
    counts: Counter[str] = Counter()

    for match in GITHUB_BLOB_RE.finditer(body):
        counts[match.group(4)] += 3

    for match in FILE_PATH_RE.finditer(body):
        counts[match.group(1)] += 1

    contract_refs = re.findall(r"\b([A-Z][A-Za-z0-9_]*\.sol)\b", body)
    for name in contract_refs:
        for path in counts:
            if path.endswith(name):
                counts[path] += 2

    if not counts:
        return None
    return counts.most_common(1)[0][0]


def contest_repo_url(contest: str) -> str:
    return f"https://github.com/code-423n4/{contest}"


def extract_commit_from_text(text: str) -> str | None:
    for line in text.splitlines():
        if NOTION_HEX_RE.search(line):
            continue
        lower = line.lower()
        if any(kw in lower for kw in ("audited", "scope", "commit", "version", "tag", "fixed")):
            m = COMMIT_SHA_RE.search(line)
            if m:
                return m.group(1).lower()
            m = SHORT_COMMIT_IN_URL_RE.search(line)
            if m:
                return m.group(1).lower()
    for match in SHORT_COMMIT_IN_URL_RE.finditer(text):
        return match.group(1).lower()
    for match in COMMIT_SHA_RE.finditer(text):
        return match.group(1).lower()
    return None


def extract_repo_urls(text: str, *, contest: str | None = None) -> list[str]:
    urls: list[str] = []
    if contest:
        urls.append(contest_repo_url(contest))
    for match in REPO_URL_RE.finditer(text):
        repo = match.group(1).rstrip(".")
        if repo.endswith("-findings"):
            continue
        url = f"https://github.com/{repo}"
        if url not in urls:
            urls.append(url)
    return urls


def parse_readme_scope(readme: str, contest: str) -> tuple[str | None, str | None]:
    repo_url = contest_repo_url(contest)
    vulnerable_commit = extract_commit_from_text(readme)

    # Prefer an explicit sponsor repo if README calls one out (rare for C4).
    for line in readme.splitlines():
        if re.search(r"public code repo|sponsor repo|source repo", line, re.I):
            for url in extract_repo_urls(line, contest=contest):
                if "code-423n4" not in url:
                    repo_url = url
                    break

    return repo_url, vulnerable_commit


def extract_fix_commit_from_issue(client: GitHubClient, owner: str, repo: str, issue_number: int) -> str | None:
    events = client.get(f"/repos/{owner}/{repo}/issues/{issue_number}/events")
    if isinstance(events, list):
        for event in events:
            commit_id = event.get("commit_id")
            if commit_id:
                return commit_id

    timeline = client.get(f"/repos/{owner}/{repo}/issues/{issue_number}/timeline")
    if isinstance(timeline, list):
        for item in timeline:
            if item.get("commit_id"):
                return item["commit_id"]
            body = item.get("body") or ""
            m = re.search(r"/commit/([0-9a-f]{7,40})", body, re.I)
            if m:
                return m.group(1)

    comments = client.get(f"/repos/{owner}/{repo}/issues/{issue_number}/comments")
    if isinstance(comments, list):
        for comment in comments:
            body = comment.get("body") or ""
            for pattern in (
                r"/commit/([0-9a-f]{7,40})",
                r"fixed in.*?([0-9a-f]{7,40})",
                r"mitigation.*?([0-9a-f]{7,40})",
            ):
                m = re.search(pattern, body, re.I)
                if m:
                    return m.group(1)
    return None


def extract_fix_from_contest_readme(readme: str) -> str | None:
    section = ""
    capture = False
    for line in readme.splitlines():
        if re.search(r"mitigation\s+review", line, re.I):
            capture = True
        if capture:
            section += line + "\n"
            if line.startswith("#") and not re.search(r"mitigation", line, re.I) and section.count("\n") > 2:
                break
    if section:
        m = re.search(r"/commit/([0-9a-f]{7,40})", section, re.I)
        if m:
            return m.group(1)
        return extract_commit_from_text(section)
    return None


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


def fetch_issue(client: GitHubClient, parsed: ParsedGitHubURL) -> dict[str, Any]:
    data = client.get(f"/repos/{parsed.owner}/{parsed.repo}/issues/{parsed.issue_number}")
    if not data:
        raise RuntimeError(f"Issue not found: {parsed.owner}/{parsed.repo}#{parsed.issue_number}")
    labels = [lbl["name"] for lbl in data.get("labels", [])]
    return {
        "title": data.get("title", ""),
        "body": data.get("body") or "",
        "labels": labels,
        "html_url": data.get("html_url", ""),
    }


def fetch_blob(client: GitHubClient, parsed: ParsedGitHubURL) -> dict[str, Any]:
    text = client.raw_file(parsed.owner, parsed.repo, parsed.blob_path or "", parsed.blob_ref)
    if not text:
        raise RuntimeError(f"Could not fetch blob: {parsed.blob_path}")
    title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else Path(parsed.blob_path or "").stem
    return {"title": title, "body": text, "labels": [], "html_url": ""}


def enrich_from_contest(client: GitHubClient, contest: str, title: str, body: str, issue_number: int | None) -> dict[str, Any]:
    owner = "code-423n4"
    readme = client.raw_file(owner, contest, "README.md") or ""
    repo_url, vulnerable_commit = parse_readme_scope(readme, contest)
    fix_commit = extract_fix_from_contest_readme(readme)

    affected_file = extract_affected_file(title, body)
    if not repo_url:
        urls = extract_repo_urls(body, contest=contest)
        repo_url = urls[0] if urls else contest_repo_url(contest)

    if not vulnerable_commit:
        for blob_match in GITHUB_BLOB_RE.finditer(body):
            ref = blob_match.group(3)
            if re.fullmatch(r"[0-9a-f]{40}", ref, re.I):
                vulnerable_commit = ref.lower()
                break

    vuln_guess, fix_guess = resolve_bug_fix_commits(client, owner, contest, affected_file)
    if not vulnerable_commit:
        vulnerable_commit = vuln_guess
    if not fix_commit:
        fix_commit = fix_guess

    if issue_number and not fix_commit:
        fix_commit = extract_fix_commit_from_issue(client, owner, f"{contest}-findings", issue_number)
        if fix_commit and not client.get(f"/repos/{owner}/{contest}/commits/{fix_commit}"):
            fix_commit = None

    return {
        "repo_url": repo_url,
        "vulnerable_commit": vulnerable_commit,
        "fix_commit": fix_commit,
        "affected_file": affected_file,
    }


def resolve_bug_fix_commits(
    client: GitHubClient, owner: str, contest: str, affected_file: str | None
) -> tuple[str | None, str | None]:
    """
    Infer (vulnerable_commit, fix_commit) from file history on the contest repo.

    Heuristic: the newest commit touching the file is likely the fix; the prior
    commit on that path is likely the vulnerable snapshot.
    """
    if not affected_file:
        return None, None
    path = affected_file.lstrip("/")
    data = client.get(f"/repos/{owner}/{contest}/commits", params={"path": path, "per_page": 20})
    if not isinstance(data, list) or len(data) < 1:
        return None, None

    fix_commit: str | None = None
    for entry in data:
        sha = entry.get("sha")
        msg = (entry.get("commit") or {}).get("message", "").lower()
        if not sha:
            continue
        if any(kw in msg for kw in ("fix", "mitigat", "h-02", "h02", "audit", "only llama", "access")):
            fix_commit = sha.lower()
            break
    if not fix_commit:
        fix_commit = data[0]["sha"].lower()

    fix_detail = client.get(f"/repos/{owner}/{contest}/commits/{fix_commit}")
    if fix_detail and isinstance(fix_detail, dict):
        parents = fix_detail.get("parents") or []
        if parents:
            return parents[0]["sha"].lower(), fix_commit

    if len(data) >= 2:
        return data[1]["sha"].lower(), fix_commit

    return None, fix_commit


def build_draft(client: GitHubClient, source_url: str) -> FindingSeed:
    parsed = parse_github_url(source_url)
    if parsed.kind == "issue":
        issue = fetch_issue(client, parsed)
        contest = contest_from_repo(parsed.repo)
        title = issue["title"]
        body = issue["body"]
        labels = issue["labels"]
        enriched = enrich_from_contest(client, contest, title, body, parsed.issue_number)
    elif parsed.blob_path and parsed.blob_path.endswith(".sol"):
        return build_draft_from_source_blob(client, parsed, source_url)
    else:
        blob = fetch_blob(client, parsed)
        contest = contest_from_repo(parsed.repo)
        title = blob["title"]
        body = blob["body"]
        labels = blob["labels"]
        enriched = enrich_from_contest(client, contest, title, body, None)

    auto = AutoResolved(
        repo_url=bool(enriched["repo_url"]),
        vulnerable_commit=bool(enriched["vulnerable_commit"]),
        fix_commit=bool(enriched["fix_commit"]),
        affected_file=bool(enriched["affected_file"]),
    )

    return FindingSeed(
        id=extract_finding_id(contest, title, labels),
        title=clean_title(title),
        source_url=source_url,
        category=guess_category(title, body),
        severity=extract_severity(title, body, labels),
        repo_url=enriched["repo_url"],
        vulnerable_commit=enriched["vulnerable_commit"],
        fix_commit=enriched["fix_commit"],
        affected_file=enriched["affected_file"],
        raw_markdown=f"# {title}\n\n{body}".strip(),
        auto_resolved=auto,
        ingested_at=datetime.now(timezone.utc).isoformat(),
    )


def build_draft_from_source_blob(
    client: GitHubClient, parsed: ParsedGitHubURL, source_url: str
) -> FindingSeed:
    """Build a draft from a source-file blob URL (commit + path in URL)."""
    contest = parsed.repo
    path = (parsed.blob_path or "").lstrip("/")
    ref = parsed.blob_ref
    vuln_commit = ref.lower() if re.fullmatch(r"[0-9a-f]{40}", ref, re.I) else None
    repo_url = contest_repo_url(contest)

    title = f"Finding at {path}"
    body = f"Source: {source_url}"
    labels: list[str] = []

    auto = AutoResolved(
        repo_url=True,
        vulnerable_commit=bool(vuln_commit),
        fix_commit=False,
        affected_file=bool(path),
    )

    return FindingSeed(
        id=f"{contest}-finding",
        title=title,
        source_url=source_url,
        category="other",
        severity="high",
        repo_url=repo_url,
        vulnerable_commit=vuln_commit,
        fix_commit=None,
        affected_file=path or None,
        raw_markdown=f"# {title}\n\n{body}",
        auto_resolved=auto,
        ingested_at=datetime.now(timezone.utc).isoformat(),
    )


def load_overrides(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Override file must be a JSON object")
    return data


def merge_overrides(draft: FindingSeed, overrides: dict[str, Any], *, source_url: str) -> FindingSeed:
    """Apply manual fallbacks; flip auto_resolved flags when values change."""
    overrides = dict(overrides)
    auto = draft.auto_resolved.model_dump()
    tracked = ("repo_url", "vulnerable_commit", "fix_commit", "affected_file")

    issue_url = overrides.pop("issue_url", None)
    if issue_url and (not draft.raw_markdown or len(draft.raw_markdown) < 200):
        try:
            issue_draft = build_draft(
                client=GitHubClient(os.environ.get("GITHUB_TOKEN")), source_url=issue_url
            )
            draft.raw_markdown = issue_draft.raw_markdown
            if draft.title.startswith("Finding at"):
                draft.title = issue_draft.title
            for field in tracked:
                if not getattr(draft, field) and getattr(issue_draft, field):
                    setattr(draft, field, getattr(issue_draft, field))
                    auto[field] = getattr(issue_draft.auto_resolved, field)
        except Exception:
            pass

    draft.source_url = source_url
    bug_spec = overrides.pop("bug_spec", None)

    for key, value in overrides.items():
        if key not in draft.model_fields or key in ("auto_resolved", "ingested_at", "source_url"):
            continue
        current = getattr(draft, key)
        if key in tracked:
            if value is None:
                setattr(draft, key, None)
                auto[key] = False
            elif str(value).lower() != str(current or "").lower():
                setattr(draft, key, value)
                auto[key] = False
            else:
                setattr(draft, key, value)
        else:
            setattr(draft, key, value)

    if bug_spec:
        draft.bug_spec = bug_spec
        if bug_spec not in draft.raw_markdown:
            draft.raw_markdown = f"# Bug spec\n\n{bug_spec}\n\n---\n\n{draft.raw_markdown}"

    draft.auto_resolved = AutoResolved(**auto)
    return draft


def print_draft_summary(draft: FindingSeed) -> None:
    table = Table(title="Auto-resolved fields", show_header=True)
    table.add_column("Field")
    table.add_column("Status")
    table.add_column("Value")

    fields = [
        ("repo_url", draft.repo_url),
        ("vulnerable_commit", draft.vulnerable_commit),
        ("fix_commit", draft.fix_commit),
        ("affected_file", draft.affected_file),
    ]
    for name, value in fields:
        ok = getattr(draft.auto_resolved, name)
        status = "[green]auto[/green]" if ok else "[yellow]missing[/yellow]"
        display = value or "—"
        if name.endswith("_commit") and value:
            display = value[:12] + "…"
        table.add_row(name, status, display)

    console.print(Panel(table, title=f"[bold]{draft.id}[/bold] — {draft.title[:70]}"))


def interactive_confirm(draft: FindingSeed) -> FindingSeed:
    print_draft_summary(draft)

    category = Prompt.ask(
        "Category",
        choices=["access-control", "state-machine", "other"],
        default=draft.category if draft.category in {"access-control", "state-machine", "other"} else "other",
    )
    severity = Prompt.ask(
        "Severity",
        choices=["critical", "high", "medium"],
        default=draft.severity if draft.severity in {"critical", "high", "medium"} else "high",
    )

    repo_url = Prompt.ask("repo_url", default=draft.repo_url or "")
    vuln = Prompt.ask("vulnerable_commit", default=draft.vulnerable_commit or "")
    fix = Prompt.ask("fix_commit (optional)", default=draft.fix_commit or "")
    affected = Prompt.ask("affected_file", default=draft.affected_file or "")

    draft.category = category
    draft.severity = severity
    draft.repo_url = repo_url or None
    draft.vulnerable_commit = vuln or None
    draft.fix_commit = fix or None
    draft.affected_file = affected or None

    if not Confirm.ask("Append to findings_seed.jsonl?", default=True):
        console.print("[red]Discarded.[/red]")
        sys.exit(0)

    return draft


def load_seed() -> list[FindingSeed]:
    if not SEED_PATH.exists() or SEED_PATH.stat().st_size == 0:
        return []
    entries: list[FindingSeed] = []
    for line in SEED_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(FindingSeed.model_validate_json(line))
    return entries


def append_seed(entry: FindingSeed) -> None:
    SEED_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SEED_PATH.open("a", encoding="utf-8") as f:
        f.write(entry.model_dump_json() + "\n")


def cmd_add(url: str, *, yes: bool = False, override_path: Path | None = None) -> None:
    load_dotenv(ROOT / ".env")
    token = os.environ.get("GITHUB_TOKEN")
    client = GitHubClient(token)

    console.print(f"[bold]Fetching[/bold] {url}")
    draft = build_draft(client, url)

    if override_path:
        overrides = load_overrides(override_path)
        draft = merge_overrides(draft, overrides, source_url=url)
        print_draft_summary(draft)

    existing = {e.id for e in load_seed()}
    if draft.id in existing:
        if yes or (override_path and not sys.stdin.isatty()):
            console.print(f"[yellow]Replacing existing {draft.id}[/yellow]")
            entries = [e for e in load_seed() if e.id != draft.id]
            SEED_PATH.write_text(
                "\n".join(e.model_dump_json() for e in entries) + ("\n" if entries else ""),
                encoding="utf-8",
            )
        elif not Confirm.ask(f"[yellow]{draft.id} already in seed file. Add anyway?[/yellow]", default=False):
            sys.exit(0)

    if yes or override_path:
        append_seed(draft)
        console.print(f"[green]Appended[/green] {draft.id} (non-interactive)")
        return

    final = interactive_confirm(draft)
    append_seed(final)
    console.print(f"[green]Appended[/green] {final.id} → {SEED_PATH}")


def cmd_list() -> None:
    entries = load_seed()
    if not entries:
        console.print("[dim]No entries in findings_seed.jsonl[/dim]")
        return

    table = Table(title="findings_seed.jsonl")
    table.add_column("id")
    table.add_column("title")
    table.add_column("category")
    table.add_column("severity")
    table.add_column("complete")

    for e in entries:
        n, total = e.completeness()
        table.add_row(
            e.id,
            (e.title[:50] + "…") if len(e.title) > 50 else e.title,
            e.category,
            e.severity,
            f"{n}/{total} auto",
        )
    console.print(table)


def parse_repo_url(repo_url: str) -> tuple[str, str]:
    parsed = urlparse(repo_url)
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        raise ValueError(f"Invalid repo_url: {repo_url}")
    return parts[0], parts[1]


def cmd_validate() -> int:
    load_dotenv(ROOT / ".env")
    token = os.environ.get("GITHUB_TOKEN")
    client = GitHubClient(token)

    entries = load_seed()
    if not entries:
        console.print("[yellow]No entries to validate.[/yellow]")
        return 1

    ok_count = 0
    table = Table(title="Validation results")
    table.add_column("id")
    table.add_column("status")
    table.add_column("notes")

    for entry in entries:
        issues: list[str] = []

        if not entry.required_complete():
            missing = [
                k
                for k, v in {
                    "repo_url": entry.repo_url,
                    "vulnerable_commit": entry.vulnerable_commit,
                    "fix_commit": entry.fix_commit,
                    "affected_file": entry.affected_file,
                }.items()
                if not v
            ]
            issues.append(f"missing: {', '.join(missing)}")

        if entry.repo_url:
            status = client.head(entry.repo_url)
            if status != 200:
                issues.append(f"repo HEAD {status}")

            try:
                owner, repo = parse_repo_url(entry.repo_url)
            except ValueError as exc:
                issues.append(str(exc))
                owner = repo = ""

            if owner and entry.vulnerable_commit:
                if not client.get(f"/repos/{owner}/{repo}/commits/{entry.vulnerable_commit}"):
                    issues.append("vulnerable_commit not found")
            if owner and entry.fix_commit:
                if not client.get(f"/repos/{owner}/{repo}/commits/{entry.fix_commit}"):
                    issues.append("fix_commit not found")
            if owner and entry.vulnerable_commit and entry.affected_file:
                path = entry.affected_file.lstrip("/")
                if not client.get(
                    f"/repos/{owner}/{repo}/contents/{path}",
                    params={"ref": entry.vulnerable_commit},
                ):
                    issues.append("affected_file missing at vulnerable_commit")

        if issues:
            table.add_row(entry.id, "[red]INVALID[/red]", "; ".join(issues))
        else:
            ok_count += 1
            table.add_row(entry.id, "[green]OK[/green]", "")

    console.print(table)
    total = len(entries)
    bad = total - ok_count
    console.print(f"\n[bold]{ok_count} of {total} findings are valid; {bad} need attention[/bold]")
    return 0 if bad == 0 else 1


def cmd_metrics() -> None:
    """Write auto-resolve telemetry for the writeup."""
    entries = load_seed()
    fields = ("repo_url", "vulnerable_commit", "fix_commit", "affected_file")
    total = len(entries)
    per_field: dict[str, dict[str, int]] = {
        f: {"auto": 0, "manual": 0} for f in fields
    }
    per_finding: list[dict[str, Any]] = []

    for e in entries:
        row: dict[str, Any] = {"id": e.id, "fields": {}}
        for f in fields:
            auto = getattr(e.auto_resolved, f)
            per_field[f]["auto" if auto else "manual"] += 1
            row["fields"][f] = "auto" if auto else "manual"
        n, _ = e.completeness()
        row["auto_count"] = n
        per_finding.append(row)

    aggregate = {
        f: {
            "auto": per_field[f]["auto"],
            "manual": per_field[f]["manual"],
            "auto_pct": round(100 * per_field[f]["auto"] / total, 1) if total else 0,
        }
        for f in fields
    }
    all_auto = sum(per_field[f]["auto"] for f in fields)
    all_manual = sum(per_field[f]["manual"] for f in fields)
    overall_pct = round(100 * all_auto / (all_auto + all_manual), 1) if (all_auto + all_manual) else 0

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": total,
        "aggregate_by_field": aggregate,
        "overall_auto_resolve_pct": overall_pct,
        "per_finding": per_finding,
        "notes": (
            "fix_commit is expected to need manual resolution for most C4 contests "
            "(mitigation commits rarely linked in findings)."
        ),
    }

    out_path = ROOT / "results" / "auto_resolve_metrics.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    console.print(f"[green]Wrote[/green] {out_path}")
    console.print(f"Overall auto-resolve rate: [bold]{overall_pct}%[/bold] ({all_auto}/{all_auto + all_manual} fields)")


def main() -> None:
    parser = argparse.ArgumentParser(description="BugMine corpus ingestion")
    sub = parser.add_subparsers(dest="command", required=True)

    add_p = sub.add_parser("add", help="Ingest one finding from a GitHub URL")
    add_p.add_argument("url")
    add_p.add_argument("-y", "--yes", action="store_true", help="Skip interactive prompts")
    add_p.add_argument("--override", type=Path, help="JSON file with manual field fallbacks")

    sub.add_parser("list", help="List seeded findings")
    sub.add_parser("validate", help="Validate seeded findings")
    sub.add_parser("metrics", help="Write results/auto_resolve_metrics.json")

    args = parser.parse_args()

    if args.command == "add":
        cmd_add(args.url, yes=args.yes, override_path=args.override)
    elif args.command == "list":
        cmd_list()
    elif args.command == "validate":
        sys.exit(cmd_validate())
    elif args.command == "metrics":
        cmd_metrics()


if __name__ == "__main__":
    main()
