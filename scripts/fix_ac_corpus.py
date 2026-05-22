"""Replace non-access-control auto-classified findings with AC ones."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "data" / "findings_seed.jsonl"

DROP_IDS = {
    "2024-06-vultisig-attacker-can-transfer-their-ilopoolnft-t",
    "2024-06-size-underwater-liquidations-don-t-take-into-",
    "2024-05-arbitrum-foundation-stakers-can-create-edges-with-non-unique",
    "2024-03-revert-lend-malicious-user-can-create-new-collateral",
}

ADD_URLS = [
    "https://github.com/code-423n4/2024-08-chakra-findings/issues/276",
    "https://github.com/code-423n4/2024-10-ronin-findings/issues/60",
    "https://github.com/code-423n4/2024-08-chakra-findings/issues/225",
    "https://github.com/code-423n4/2024-07-traitforge-findings/issues/955",
]


def main() -> None:
    lines = []
    for line in SEED.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        if json.loads(line)["id"] not in DROP_IDS:
            lines.append(line)
    SEED.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Kept {len(lines)} findings after dropping misclassified")

    for url in ADD_URLS:
        proc = subprocess.run(
            [sys.executable, "-m", "src.fetch", "add", url, "-y"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        print(proc.stdout.strip() or proc.stderr.strip())


if __name__ == "__main__":
    main()
