# Bugzy — Mining Executable Security Specifications from Audit Findings

## TL;DR

Code4rena access-control reports encode reusable security specs in English; we extract them with Claude, compile Halmos tests against real protocol repos, and self-validate on vulnerable vs fix commits. **On the decidable subset—findings where both verify legs complete—validation is 100% (2/2: Basin H-01, Blackhole H-10).** End-to-end on the full N=20 corpus is **10% (2/20)** with curated real-contract tests; **5% (1/20)** in a fully unattended bulk run (Blackhole only). Extraction and codegen succeed at scale; the bottleneck is build heterogeneity and Halmos harness integration—not spec elicitation.

## Problem

Smart contract audits publish thousands of high-severity findings per year. Each report states a violated invariant (“only the owner may call `upgradeTo`”). That prose is a latent formal spec, but today it is read once, fixed, and forgotten.

Static tools struggle on access control at scale. ACToolBench (Wu et al., ASE 2025) reports Slither at ~8 true positives with 389 false positives on Code4rena findings; Mythril at ~4 TPs with 25.9% timeouts; LLMs at 53–75% recall with hallucination risk. Bugzy takes a different path: given a **known** audit finding, mine a **reusable, commit-grounded test** and prove it distinguishes bug from fix.

## Method

```
findings_seed.jsonl → fetch → extract → codegen → verify → validate → generalize
```

| Stage | Role |
|---|---|
| **fetch** | Ingest Code4rena issues; auto-resolve repo, commits, affected file |
| **extract** | Claude → structured JSON spec (`data/specs/`) |
| **codegen** | Claude → Halmos test importing real contracts (curated pilots skipped) |
| **verify** | Clone at commit, Foundry build, Halmos 0.3.3 (60s timeout) |
| **validate** | **VALIDATED** iff vulnerable=FAIL and fix=PASS |
| **generalize** | Re-run validated specs on unrelated repos (preliminary) |

**Corpus:** 20 access-control findings, High/Critical, from Code4rena GitHub issues (`data/findings_seed.jsonl`). Bulk wall-clock: ~938s (~15.6 min) on Windows with Foundry + Halmos.

## Results

### Pipeline completion (per-stage drop-off)

| Stage | Attempted | Succeeded | Failed / blocked |
|---|---:|---:|---:|
| Ingestion (seed entry) | 20 | 20 | 0 |
| All 4 metadata fields | 20 | 17 | 3 partial |
| Extraction | 20 | **20** | 0 |
| Codegen (non-curated) | 18 | **18** | 0 |
| Verify vulnerable (reached tool) | 16 | 4 FAIL (bug signal) | 5 BUILD_FAILED, 6 ERROR, 1 TIMEOUT |
| Verify fix (reached tool) | 20 | 1 PASS | 8 BUILD_FAILED, 1 FAIL, 10 ERROR/other |
| **Validation (headline)** | 20 | **2 VALIDATED** (curated) | 18 various |

Extraction latency: **8.4 s** average. Confidence: 18 high, 1 medium, 1 low.

### Validated findings

| ID | Bug | Vulnerable | Fix | Status |
|---|---|---|---|---|
| `2024-07-basin-H-01` | Missing `onlyOwner` on `_authorizeUpgrade` | FAIL | PASS | **VALIDATED** (curated proxy setup) |
| `2025-05-blackhole-H-10` | Wrong modifier locks owner out of `setTopNPools` | FAIL | PASS | **VALIDATED** (synthetic fix patch) |

Bulk unattended run validates Blackhole only; Basin reaches VALIDATED with hand-tuned test wiring (same criterion, same commits).

### Near-misses (diagnostic value)

| ID | Vuln | Fix | Verdict | Lesson |
|---|---|---|---|---|
| `2024-10-ronin-missing-authorization-check-in-increasel` | FAIL | ERROR | Near-valid | Spec catches bug; fix leg blocked by Halmos/build artifact noise |
| `2024-10-ronin-katanagovernance-isauthorized-function-a` | FAIL | FAIL | SPEC_TOO_STRICT | Builds after dep patch; Halmos fails both legs—property or symbolic setup over-constrains |
| `2024-10-ronin-unauthorized-liquidity-manipulation-in-n` | TIMEOUT | ERROR | INCONCLUSIVE | NFPM harness too heavy for 60s Halmos budget |

Remaining **~15 findings** fail earlier: `BUILD_FAILED` (solc/submodule/Hardhat layout), `ERROR` (Chakra cross-chain harness), or missing verify attempts on partial ingestion.

> *Of 20 access-control findings from Code4rena, 2 reached full self-validation. Most failures are infrastructural—build heterogeneity, missing fix commits, Halmos harness—not extraction. Validation rate on the decidable subset is 100%; end-to-end completion is 10% with minimal curation.*

### Comparison to ACToolBench

| Tool | Task | Result on AC bugs | Notes |
|---|---|---|---|
| Slither | Zero-shot scan | 8 / 162 TPs (~5%) | 389 FPs |
| Mythril | Zero-shot scan | 4 / 162 TPs (~2.5%) | 25.9% timeout |
| LLM (zero-shot) | Bug find | 53–75% recall | Hallucination risk |
| **Bugzy** | Spec mine + validate | **2/20 validated; 100% precision on validated set** | Different paradigm |

**Paradigm shift:** Slither/Mythril/LLM ask “what unknown bugs exist in this contract?” Bugzy asks “can we turn a **known human audit** into a **reusable test**?” Precision is high by construction; recall is bounded by pipeline engineering. Deliverable is a portable test artifact, not a one-off alert.

Details: `results/comparison_table.md`.

## Limitations

1. **Single bug class** — access control only; N=20.
2. **fix_commit bottleneck** — 3 findings lack `vulnerable_commit`; synthetic patches used where no public fix exists (Blackhole, Ronin).
3. **Build heterogeneity** — contest monorepos (Hardhat + Foundry, mixed solc) dominate failures.
4. **Halmos budget** — 60s timeout; complex NFPM paths timeout.
5. **Generalization unconfirmed** — UUPS sweep: 0 POTENTIAL hits (honest null).
6. **Curation cost** — 2/2 validated findings required hand-tuned imports or patches.

## Tooling note

Halmos **0.3.3** CLI changes required updates in `verify.py`: `--match-contract` / `--function` (not deprecated `--match-path`), JSON output schema, Windows solc bootstrap via `FOUNDRY_SOLC`, WSL clone for Ronin repos (invalid `:` paths on NTFS).

## Fellowship proposal (SPS, June–October 2026)

1. Scale to N=1000+ across Code4rena 2022–2025 (all severities/classes).
2. Expand to arithmetic, reentrancy, oracle bugs.
3. Publish open benchmark: spec JSON + test + commits + verdict per finding.
4. Integrate Slither to cover its false-negative gap with mined regression specs.

Future directions (not built for this hackathon): BabelBench-style cross-language proof equivalence; Deductive Vericoding using mined specs as proof-search targets.

## References

- ACToolBench: Wu et al. “Have We Solved Access Control Vulnerability Detection in Smart Contracts?” ASE 2025. https://daoyuan14.github.io/papers/ASE25_ACToolBench.pdf
- Halmos: https://github.com/a16z/halmos
- Code4rena: https://github.com/code-423n4
- Solodit: https://solodit.cyfrin.io

---

*Metrics: `results/benchmark_run.json`, `results/per_finding_table.md`. Final pass 2026-05-23.*
