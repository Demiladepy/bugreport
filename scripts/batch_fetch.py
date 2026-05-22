"""Batch-ingest C4 findings into findings_seed.jsonl (non-interactive)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

NEW_URLS = [
    "https://github.com/code-423n4/2024-10-ronin-findings/issues/67",
    "https://github.com/code-423n4/2024-10-ronin-findings/issues/43",
    "https://github.com/code-423n4/2024-08-chakra-findings/issues/393",
    "https://github.com/code-423n4/2024-08-chakra-findings/issues/384",
    "https://github.com/code-423n4/2024-08-chakra-findings/issues/193",
    "https://github.com/code-423n4/2024-08-chakra-findings/issues/208",
    "https://github.com/code-423n4/2024-08-chakra-findings/issues/111",
    "https://github.com/code-423n4/2024-07-loopfi-findings/issues/37",
    "https://github.com/code-423n4/2024-07-traitforge-findings/issues/915",
    "https://github.com/code-423n4/2024-07-traitforge-findings/issues/839",
    "https://github.com/code-423n4/2024-09-fenix-finance-findings/issues/15",
    "https://github.com/code-423n4/2024-10-kleidi-findings/issues/40",
    "https://github.com/code-423n4/2024-06-vultisig-findings/issues/82",
    "https://github.com/code-423n4/2024-06-size-findings/issues/75",
    "https://github.com/code-423n4/2024-05-arbitrum-foundation-findings/issues/52",
    "https://github.com/code-423n4/2024-03-revert-lend-findings/issues/58",
    "https://github.com/code-423n4/2023-11-kelp-findings/issues/38",
]

KEEP_IDS = {
    "2023-06-llama-H-02",
    "2024-07-basin-H-01",
    "2025-05-blackhole-H-10",
}


def main() -> None:
    seed_path = ROOT / "data" / "findings_seed.jsonl"
    import json

    kept: list[str] = []
    if seed_path.exists():
        for line in seed_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            data = json.loads(line)
            if data["id"] in KEEP_IDS:
                kept.append(line)

    seed_path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    print(f"Kept {len(kept)} existing findings")

    ok = fail = 0
    for url in NEW_URLS:
        print(f"Fetching {url}...")
        proc = subprocess.run(
            [sys.executable, "-m", "src.fetch", "add", url, "-y"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            ok += 1
            print(proc.stdout.strip() or "OK")
        else:
            fail += 1
            print(f"FAIL: {proc.stderr or proc.stdout}")

    print(f"\nDone: {ok} added, {fail} failed")


if __name__ == "__main__":
    main()
