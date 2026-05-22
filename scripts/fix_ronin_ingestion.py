"""Update Ronin findings in findings_seed.jsonl with fix commits and protocol repos."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "data" / "findings_seed.jsonl"

UPDATES = {
    "2024-10-ronin-missing-authorization-check-in-increasel": {
        "repo_url": "https://github.com/ronin-chain/katana-v3-contracts",
        "vulnerable_commit": "03c80179e04f40d96f06c451ea494bb18f2a58fc",
        "fix_commit": "03c80179e04f40d96f06c451ea494bb18f2a58fc",
        "affected_file": "src/periphery/NonfungiblePositionManager.sol",
        "synthetic_fix": True,
        "synthetic_fix_note": (
            "data/synthetic/2024-10-ronin-missing-authorization-check-in-increasel.patch: "
            "add isAuthorizedForToken to increaseLiquidity (no public sponsor commit found)"
        ),
        "bug_spec": (
            "For any caller that is not the owner or approved operator of tokenId, "
            "increaseLiquidity(tokenId, ...) must revert."
        ),
    },
    "2024-10-ronin-unauthorized-liquidity-manipulation-in-n": {
        "repo_url": "https://github.com/ronin-chain/katana-v3-contracts",
        "vulnerable_commit": "03c80179e04f40d96f06c451ea494bb18f2a58fc",
        "fix_commit": "03c80179e04f40d96f06c451ea494bb18f2a58fc",
        "affected_file": "src/periphery/NonfungiblePositionManager.sol",
        "synthetic_fix": True,
        "synthetic_fix_note": (
            "data/synthetic/2024-10-ronin-unauthorized-liquidity-manipulation-in-n.patch: "
            "add isAuthorizedForToken to increaseLiquidity (duplicate of issue #67; no public fix commit)"
        ),
        "bug_spec": (
            "For any caller that is not the owner or approved operator of tokenId, "
            "increaseLiquidity(tokenId, ...) must revert."
        ),
    },
    "2024-10-ronin-katanagovernance-isauthorized-function-a": {
        "repo_url": "https://github.com/ronin-chain/katana-operation-contracts",
        "vulnerable_commit": "27f9d28e00958bf3494fa405a8a5acdcd5ecdc5d",
        "fix_commit": "27f9d28e00958bf3494fa405a8a5acdcd5ecdc5d",
        "affected_file": "src/governance/KatanaGovernance.sol",
        "synthetic_fix": True,
        "synthetic_fix_note": (
            "data/synthetic/2024-10-ronin-katanagovernance-isauthorized-function-a.patch: "
            "block.timestamp > expiry -> < expiry per warden mitigation (no public sponsor commit found)"
        ),
        "bug_spec": (
            "When whitelist expiry has passed, _isAuthorized must not grant access to arbitrary accounts."
        ),
    },
}


def main() -> None:
    rows: list[dict] = []
    for line in SEED.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row["id"] in UPDATES:
            row.update(UPDATES[row["id"]])
            if row.get("auto_resolved"):
                row["auto_resolved"]["fix_commit"] = False
                row["auto_resolved"]["repo_url"] = False
        rows.append(row)

    SEED.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    for fid in UPDATES:
        print(f"updated {fid}")


if __name__ == "__main__":
    main()
