"""Inspect Ronin vulnerable vs candidate fix commits."""
import base64
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
token = os.environ.get("GITHUB_TOKEN")
h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}


def grep(repo: str, sha: str, path: str, needle: str) -> None:
    r = requests.get(
        f"https://api.github.com/repos/{repo}/contents/{path}",
        params={"ref": sha},
        headers=h,
        timeout=60,
    )
    if r.status_code != 200:
        print("ERR", repo, sha[:12], r.status_code)
        return
    text = base64.b64decode(r.json()["content"]).decode("utf-8", errors="replace")
    hits = [f"{i}:{line.strip()}" for i, line in enumerate(text.splitlines(), 1) if needle.lower() in line.lower()]
    print(sha[:12], f"needle={needle!r}", "hits", len(hits))
    for x in hits[:10]:
        print(" ", x[:140])


def show_function(repo: str, sha: str, path: str, fn: str) -> None:
    r = requests.get(
        f"https://api.github.com/repos/{repo}/contents/{path}",
        params={"ref": sha},
        headers=h,
        timeout=60,
    )
    if r.status_code != 200:
        print("ERR", repo, sha[:12], r.status_code)
        return
    text = base64.b64decode(r.json()["content"]).decode("utf-8", errors="replace")
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if fn in l and "function" in l), None)
    if start is None:
        print(sha[:12], fn, "NOT FOUND")
        return
    print(f"\n=== {repo} @ {sha[:12]} {fn} ===")
    for line in lines[start : start + 25]:
        print(line)


if __name__ == "__main__":
    vuln = "03c80179e04f40d96f06c451ea494bb18f2a58fc"
    print("=== NPM ===")
    for sha in [vuln, "746b62959fe4", "a9807503ef43"]:
        show_function(
            "ronin-chain/katana-v3-contracts",
            sha,
            "src/periphery/NonfungiblePositionManager.sol",
            "increaseLiquidity",
        )

    gov_vuln = "27f9d28e00958bf3494fa405a8a5acdcd5ecdc5d"
    print("\n=== Governance ===")
    for sha in [gov_vuln, "053e426f868f", "98b3f166b11a", "3f4ae3799657"]:
        show_function(
            "ronin-chain/katana-operation-contracts",
            sha,
            "src/governance/KatanaGovernance.sol",
            "_isAuthorized",
        )
