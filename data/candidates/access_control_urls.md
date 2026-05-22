# Candidate Solodit / Code4rena URLs (Access Control, High/Critical)

Discovered via GitHub search (`org:code-423n4` + access-control keywords).  
Ingested with `python -m src.fetch add <url> -y` (no manual field correction).

## Kept from pilot (3)

- https://github.com/code-423n4/2023-06-llama-findings/issues/62
- https://github.com/code-423n4/2024-07-basin/blob/7d5aacbb144d0ba0bc358dfde6e0cc913d25310e/src/WellUpgradeable.sol
- https://github.com/code-423n4/2025-05-blackhole/blob/92fff849d3b266e609e6d63478c4164d9f608e91/contracts/SetterTopNPoolsStrategy.sol

## New batch (17)

1. https://github.com/code-423n4/2024-10-ronin-findings/issues/67 — `increaseLiquidity` missing auth
2. https://github.com/code-423n4/2024-10-ronin-findings/issues/43 — `_isAuthorized` expiry bypass
3. https://github.com/code-423n4/2024-08-chakra-findings/issues/393 — `_Settlement_init` missing AC
4. https://github.com/code-423n4/2024-08-chakra-findings/issues/384 — `__TokenRoles_init` unprotected
5. https://github.com/code-423n4/2024-08-chakra-findings/issues/193 — implementation ownership steal
6. https://github.com/code-423n4/2024-08-chakra-findings/issues/208 — admin role not revoked on transfer
7. https://github.com/code-423n4/2024-08-chakra-findings/issues/111 — `required_validators` bypass
8. https://github.com/code-423n4/2024-07-loopfi-findings/issues/37 — `borrow`/`repay` missing `whenNotPaused`
9. https://github.com/code-423n4/2024-07-traitforge-findings/issues/915 — `initializeAlphaIndices` wrong modifier
10. https://github.com/code-423n4/2024-07-traitforge-findings/issues/839 — pause/unpause AC (H-1)
11. https://github.com/code-423n4/2024-09-fenix-finance-findings/issues/15 — `killGauge` weights
12. https://github.com/code-423n4/2024-10-kleidi-findings/issues/40 — `_updatePauseDuration` checks
13. https://github.com/code-423n4/2023-11-kelp-findings/issues/38 — asset deletion AC
14. https://github.com/code-423n4/2024-08-chakra-findings/issues/276 — `__TokenRoles_init` AC
15. https://github.com/code-423n4/2024-10-ronin-findings/issues/60 — NFPM liquidity manipulation
16. https://github.com/code-423n4/2024-08-chakra-findings/issues/225 — nonce manipulation AC
17. https://github.com/code-423n4/2024-07-traitforge-findings/issues/955 — `TraitForgeNft` mint AC

## Excluded from benchmark (state-machine example for writeup)

- https://github.com/code-423n4/2024-03-neobase — gauge removal / `vote_for_gauge_weights` (cited as generalization beyond access-control, not in N=20 run)
