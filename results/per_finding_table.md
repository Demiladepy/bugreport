# Per-finding pipeline outcomes

| ID | Title | Ingest | Extract | Codegen | Vuln verify | Fix verify | Validation |
|---|---|---|---|---|---|---|---|
| `2023-06-llama-H-02` | Anyone can change approval/disapproval threshold for any action using  | complete | ok | ok | BUILD_FAILED | BUILD_FAILED | INCONCLUSIVE |
| `2024-07-basin-H-01` | Anyone can upgrade WellUpgradeable — missing onlyOwner on _authorizeUp | complete | ok | ok | FAIL | ERROR | INCONCLUSIVE |
| `2025-05-blackhole-H-10` | Misaligned access control on setTopNPools — owner locked out | complete | ok | ok | FAIL | PASS | VALIDATED |
| `2024-10-ronin-missing-authorization-check-in-increasel` | Missing authorization check in `increaseLiquidity` permits unauthorize | complete | ok | ok | FAIL | ERROR | INCONCLUSIVE |
| `2024-10-ronin-katanagovernance-isauthorized-function-a` | KatanaGovernance::_isAuthorized function allows user to perform action | complete | ok | ok | FAIL | FAIL | SPEC_TOO_STRICT |
| `2024-08-chakra-missing-access-control-in-settlement-ini` | Missing Access Control in _Settlement_init and()  _Settlement_handler_ | complete | ok | ok | ERROR | ERROR | INCONCLUSIVE |
| `2024-08-chakra-unprotected-initializer-in-tokenroles-in` | Unprotected initializer in '__TokenRoles_init' function let any user c | complete | ok | ok | ERROR | ERROR | INCONCLUSIVE |
| `2024-08-chakra-an-attacker-can-steal-ownership-of-imple` | An attacker can steal ownership of implementation contracts `Settlemen | partial | ok | ok | — | ERROR | INCONCLUSIVE |
| `2024-08-chakra-default-admin-role-not-revoked-on-owners` | Default admin role not revoked on ownership transfer provides old owne | complete | ok | ok | ERROR | ERROR | INCONCLUSIVE |
| `2024-08-chakra-the-required-validators-check-can-be-byp` | The required_validators check can be bypassed in the `SettlementSignat | complete | ok | ok | ERROR | ERROR | INCONCLUSIVE |
| `2024-07-loopfi-due-to-missing-whennotpaused-modifiers-o` | Due to missing whenNotPaused modifiers on "borrow" and "repay" CDPVaul | complete | ok | ok | BUILD_FAILED | BUILD_FAILED | INCONCLUSIVE |
| `2024-07-traitforge-initializealphaindices-uses-the-wrong-mo` | `initializeAlphaIndices` uses the wrong modifier and correction for th | complete | ok | ok | — | BUILD_FAILED | INCONCLUSIVE |
| `2024-07-traitforge-H-1` | Inability to Pause or Unpause Critical Contract Functions | complete | ok | ok | BUILD_FAILED | BUILD_FAILED | INCONCLUSIVE |
| `2024-09-fenix-finance-the-killgauge-function-should-set-the-we` | The `killGauge` function should set the `weightsPerEpoch` value to zer | partial | ok | ok | — | BUILD_FAILED | INCONCLUSIVE |
| `2024-10-kleidi-missing-pause-time-checks-in-updatepause` | Missing Pause Time Checks in `_updatePauseDuration` Function | complete | ok | ok | BUILD_FAILED | BUILD_FAILED | INCONCLUSIVE |
| `2023-11-kelp-lack-of-deletion-mechanism-for-assets-po` | Lack of deletion mechanism for assets poses security risk in the proto | complete | ok | ok | BUILD_FAILED | BUILD_FAILED | INCONCLUSIVE |
| `2024-08-chakra-missing-access-control-over-tokenroles-t` | Missing Access control over `TokenRoles::__TokenRoles_init` function,  | complete | ok | ok | ERROR | ERROR | INCONCLUSIVE |
| `2024-10-ronin-unauthorized-liquidity-manipulation-in-n` | Unauthorized Liquidity Manipulation in NonfungiblePositionManager Cont | complete | ok | ok | TIMEOUT | ERROR | INCONCLUSIVE |
| `2024-08-chakra-unauthorized-nonce-manipulation-in-cross` | Unauthorized Nonce Manipulation in Cross-Chain Transactions Causing tx | complete | ok | ok | ERROR | ERROR | INCONCLUSIVE |
| `2024-07-traitforge-traitforgenft-is-only-able-to-mint-gener` | `TraitForgeNft` is only able to `mint generation 1` due to wrong acces | partial | ok | ok | — | BUILD_FAILED | INCONCLUSIVE |

## Validated findings

- `2025-05-blackhole-H-10`
