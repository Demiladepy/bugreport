# Bugzy: Mining Executable Security Specifications from Audit Findings

**A commit-grounded pipeline for turning Code4rena access-control reports into self-validated Halmos property tests.**

| | |
|---|---|
| **Task** | Spec elicitation + symbolic validation (not zero-shot bug finding) |
| **Corpus** | N=20 Code4rena access-control findings (High/Critical) |
| **Verifier** | Halmos 0.3.3 (SMT-based symbolic execution) |
| **LLM** | Claude Sonnet (extraction + test codegen) |
| **Paper-style writeup** | [`RESULTS.md`](RESULTS.md) |
| **Full benchmark JSON** | [`results/benchmark_run.json`](results/benchmark_run.json) |



## Abstract

Smart contract audits encode thousands of implicit security specifications in natural language. These properties are fixed once and rarely reused. We study whether modern LLMs can **extract** formal specs from audit prose, **compile** them into symbolic tests over real protocol code, and **self-validate** them against public git history (vulnerable commit vs fix commit).

We introduce **Bugzy**, a six-stage pipeline (`fetch → extract → codegen → verify → validate → generalize`) evaluated on 20 access-control findings from Code4rena. Extraction succeeds on **20/20** findings; automated test codegen on **18/18** non-curated entries. **Two findings** reach full self-validation (Basin H-01, Blackhole H-10): Halmos **FAIL** on the vulnerable commit, **PASS** on the fix. On the **decidable subset** where both verification legs complete, validation precision is **100% (2/2)**. End-to-end completion on the full corpus is **10% (2/20)** with minimal curation; **5% (1/20)** in a fully unattended bulk run.

We characterize failure modes for the remaining 18 findings: build heterogeneity (mixed solc, Hardhat/Foundry monorepos), missing or synthetic fix commits, and Halmos harness integration—not spec extraction. We compare against ACToolBench (Wu et al., ASE 2025) and argue Bugzy occupies an orthogonal point in the design space: **high-precision, reusable tests mined from known human audits**, rather than noisy zero-shot discovery.

---

## 1. Motivation

### 1.1 The specification waste problem

Each Code4rena contest produces dozens of High-severity findings. A typical report states a violated invariant in prose—for example, *"only the owner may call `_authorizeUpgrade`"* or *"the owner must be able to call `setTopNPools`"*. Sponsors patch the code; the report archives. The **specification** is never lifted into a durable, executable artifact that can guard future code.

As AI-assisted development increases contract throughput, this waste becomes costly. We need mechanisms to **bootstrap formal properties from prior human audit work** and re-apply them as regression tests.

### 1.2 Limitations of zero-shot detection

ACToolBench evaluates access-control detection on Code4rena findings with tools that scan contracts without prior knowledge of the bug:

| Tool | Paradigm | Reported result (ACToolBench) |
|---|---|---|
| Slither | Static analysis | ~8 TP / 162 findings; **389 FP** |
| Mythril | Symbolic execution | ~4 TP / 162; **25.9% timeout** |
| GPT-4-class LLM | Zero-shot bug find | 53–75% recall; hallucination risk |

These systems answer: *"What unknown bugs exist in this contract?"* Bugzy answers a different question: *"Given a known audit finding, can we produce a test that provably distinguishes the bug from its fix?"* Precision is high by construction; recall is bounded by pipeline engineering and corpus coverage.

### 1.3 Research questions

1. **RQ1 (Elicitation):** Can LLMs reliably extract structured formal specs from contest-grade audit markdown?
2. **RQ2 (Validation):** Do generated Halmos tests **fail** on vulnerable commits and **pass** on fix commits without manual proof?
3. **RQ3 (Scale):** Where does the pipeline break when applied uniformly to N=20 findings without per-finding tuning?
4. **RQ4 (Reuse):** Can validated specs transfer to unrelated contracts in the same vulnerability class?



## 2. Method

### 2.1 Pipeline overview

```
findings_seed.jsonl
       │
       ▼
  ┌─────────┐     GitHub issue + auto-resolved metadata
  │  fetch  │ ──► repo_url, vulnerable_commit, fix_commit, affected_file
  └────┬────┘
       ▼
  ┌─────────┐     Claude → JSON property schema
  │ extract │ ──► data/specs/{id}.json
  └────┬────┘
       ▼
  ┌─────────┐     Claude → Solidity Halmos test (imports real contracts)
  │ codegen │ ──► data/tests/{id}/Test*.t.sol
  └────┬────┘
       ▼
  ┌─────────┐     Clone @ commit, forge build, halmos --function check_*
  │ verify  │ ──► PASS | FAIL | BUILD_FAILED | TIMEOUT | ERROR
  └────┬────┘
       ▼
  ┌──────────┐    VALIDATED iff verify(vuln)=FAIL ∧ verify(fix)=PASS
  │ validate │
  └────┬─────┘
       ▼
  ┌────────────┐  Apply spec to unrelated repos (UUPS pool, etc.)
  │ generalize │
  └────────────┘
```

### 2.2 Self-validation criterion

A mined spec is **VALIDATED** if and only if:

```
verify(spec, vulnerable_commit) = FAIL    # catches the bug
verify(spec, fix_commit)        = PASS    # no false alarm on patched code
```

Outcomes `BUILD_FAILED`, `TIMEOUT`, and `ERROR` are **inconclusive**: they do not falsify the spec, but they block a validation verdict. Additional labels:

| Label | Meaning |
|---|---|
| `SPEC_TOO_WEAK` | Passes on both vulnerable and fix |
| `SPEC_TOO_STRICT` | Fails on both |
| `CANNOT_VALIDATE` | Missing `fix_commit` or test artifact |

### 2.3 Corpus construction

- **Source:** Code4rena GitHub issue URLs (`code-423n4/*-findings`), discovered via keyword search (`scripts/discover_findings.py`).
- **Filter:** High/Critical severity, access-control category, function-level specificity.
- **Size:** N=20 (includes 3 pilot seeds: Llama, Basin, Blackhole).
- **Metadata:** Each row in `data/findings_seed.jsonl` links `source_url`, `repo_url`, commits, and `affected_file`. Auto-resolve fills ~90% of fields; Ronin entries use **synthetic fix patches** where no public sponsor commit exists (`data/synthetic/*.patch`).

We align domain and severity with ACToolBench for comparability, but **do not** reuse their exact 162-finding set.

### 2.4 Models and tools

| Component | Version / config |
|---|---|
| Extraction LLM | Claude Sonnet via Anthropic API |
| Codegen LLM | Claude Sonnet (same) |
| Build | Foundry (`forge build`, `forge install`) |
| Symbolic exec | Halmos 0.3.3, 60s timeout per `check_*` function |
| Curated pilots | Basin H-01, Blackhole H-10 (+ Ronin harness work); listed in `data/tests/curated.txt` |

### 2.5 Experimental protocol (bulk benchmark)

Unattended run with no per-finding manual intervention:

```bash
python -m src.extract all
python -m src.codegen all
python -m src.verify all --commit vulnerable
python -m src.verify all --commit fix
python -m src.validate all --use-cached
python -m src.benchmark report
```

Wall-clock: **938 s (~15.6 min)** on Windows 11, Foundry 1.5+, Halmos 0.3.3. Log: `results/benchmark_wallclock.log`.

---

## 3. Results (summary)

Full tables: [`RESULTS.md`](RESULTS.md) · per-finding: [`results/per_finding_table.md`](results/per_finding_table.md)

### 3.1 Pipeline funnel

| Stage | Attempted | Succeeded | Notes |
|---:|---:|---:|---|
| Ingestion | 20 | 20 | 17/20 with all 4 metadata fields |
| Extraction | 20 | **20** | 18 high / 1 medium / 1 low confidence; 8.4 s avg |
| Codegen | 18 | **18** | 2 curated pilots skipped |
| Verify (vulnerable) | 16 | 4 FAIL | 5 BUILD_FAILED, 6 ERROR, 1 TIMEOUT |
| Verify (fix) | 20 | 1 PASS | 8 BUILD_FAILED, remainder ERROR/other |
| **Validation** | 20 | **2** | Basin + Blackhole (curated real-contract tests) |

### 3.2 Validated findings

| ID | Property (abbrev.) | Vuln | Fix | Notes |
|---|---|---|---|---|
| [`2024-07-basin-H-01`](data/specs/2024-07-basin-H-01.json) | Non-owner `upgradeTo` must revert | FAIL | PASS | UUPS proxy + Aquifer setup (curated) |
| [`2025-05-blackhole-H-10`](data/specs/2025-05-blackhole-H-10.json) | Owner must call `setTopNPools` | FAIL | PASS | Synthetic fix patch (no public sponsor commit) |

### 3.3 Near-misses with diagnostic value

| ID | Vuln | Fix | Verdict | Interpretation |
|---|---|---|---|---|
| Ronin NPM #67 | FAIL | ERROR | Near-valid | Spec catches bug; fix leg blocked by build/Halmos noise |
| Ronin governance | FAIL | FAIL | SPEC_TOO_STRICT | Builds; property or symbolic setup over-constrains |
| Ronin NFPM duplicate | TIMEOUT | ERROR | INCONCLUSIVE | Harness exceeds 60s Halmos budget |

### 3.4 Headline claims (use precisely)

| Claim | Value | Scope |
|---|---|---|
| Extraction success | **100%** (20/20) | Full corpus |
| Codegen success | **100%** (18/18 non-curated) | Generated tests compile syntactically |
| Validation precision | **100%** (2/2) | Decidable subset with completed verify legs |
| End-to-end validation | **10%** (2/20) | With curated real-contract tests |
| Unattended end-to-end | **5%** (1/20) | Bulk run without curation |
| Halmos timeout rate | **1/16** vulnerable attempts | Not the dominant failure mode |

**We do not claim** AI can replace auditors, that specs are complete or sound, or competitive zero-shot recall with Slither/Mythril.

---

## 4. Repository layout

```
bugreport/
├── data/
│   ├── findings_seed.jsonl      # Benchmark corpus (source of truth)
│   ├── specs/                   # LLM-extracted formal properties (JSON)
│   ├── tests/                   # Generated + curated Halmos tests
│   ├── synthetic/               # Synthetic fix patches (Blackhole, Ronin)
│   ├── overrides/               # Per-finding metadata overrides
│   └── targets/                 # Generalization target lists
├── src/
│   ├── fetch.py                 # Ingestion + auto-resolve
│   ├── extract.py               # Spec elicitation (Claude)
│   ├── codegen.py               # Test generation (Claude)
│   ├── verify.py                # Foundry + Halmos runner
│   ├── validate.py              # Self-validation loop
│   ├── generalize.py            # Cross-repo spec sweep
│   └── benchmark.py             # Aggregate metrics report
├── results/
│   ├── benchmark_run.json       # Headline metrics (machine-readable)
│   ├── per_finding_table.md     # All 20 rows
│   ├── validation/              # Per-finding validation verdicts
│   └── verify/                  # Per-commit Halmos outcomes
├── RESULTS.md                   # Paper-style evaluation writeup
└── PROJECT.md                   # Original problem statement + scope
```

Cloned protocol repos (`data/repos/`) and API secrets (`.env`) are **gitignored** and produced at verify time.

---

## 5. Reproducibility

### 5.1 Prerequisites

| Tool | Purpose | Install |
|---|---|---|
| Python ≥3.11 | Pipeline CLI | `pip install -r requirements.txt` |
| Foundry | `forge build`, `forge install` | [getfoundry.sh](https://book.getfoundry.sh/getting-started/installation) |
| Halmos 0.3.3 | Symbolic execution | `pip install halmos` |
| Git | Clone + checkout commits | system package |
| WSL (Windows only) | Ronin repos with `:` in paths | Ubuntu on WSL2 |

### 5.2 Environment

```powershell
# Windows PowerShell
cd C:\Users\User\Desktop\nothing\bugreport
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# Set ANTHROPIC_API_KEY (required for extract/codegen)
# Set GITHUB_TOKEN (optional, rate limits)
```

```bash
# WSL / Linux
cd /mnt/c/Users/User/Desktop/nothing/bugreport   # adjust path
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 5.3 Quick verification (no API calls)

Inspect pre-computed artifacts from the published benchmark:

```powershell
python -m json.tool results\benchmark_run.json
Get-Content results\per_finding_table.md
Get-Content results\validation\2024-07-basin-H-01.json
Get-Content results\validation\2025-05-blackhole-H-10.json
Get-Content RESULTS.md -Head 30
```

### 5.4 Full pipeline (single finding)

```powershell
# Show extracted spec (cached on disk)
python -m src.extract show 2024-07-basin-H-01

# Live Halmos on vulnerable + fix commits (slow: clone + build)
python -m src.verify one 2024-07-basin-H-01 --commit vulnerable
python -m src.verify one 2024-07-basin-H-01 --commit fix

# Full validation verdict
python -m src.validate one 2024-07-basin-H-01 --use-cached
```

### 5.5 Reproduce bulk benchmark

```powershell
python -m src.extract all
python -m src.codegen all
python -m src.verify all --commit vulnerable
python -m src.verify all --commit fix
python -m src.validate all --use-cached
python -m src.benchmark report
```

Expect ~15–20 minutes wall-clock depending on network and cache state.

---

## 6. Failure taxonomy

We publish per-stage outcomes rather than reporting validation rate alone. Dominant failure modes on N=20:

| Mode | Approx. count | Example |
|---|---:|---|
| `BUILD_FAILED` | 8–10 | Missing submodules, solc version skew, Hardhat layout |
| `ERROR` | 6–8 | Halmos harness mismatch, Chakra cross-chain init |
| `TIMEOUT` | 1 | Ronin NFPM (complex deploy graph) |
| `SPEC_TOO_STRICT` | 1 | Ronin governance (both legs FAIL) |
| Near-valid | 1 | Ronin NPM (FAIL vuln, ERROR fix) |

Extraction and codegen are **not** the bottleneck at current scale. Engineering effort concentrates on **repo integration** and **commit-grounded ground truth**.

---

## 7. Limitations and future work

**Limitations**

1. Single bug class (access control); N=20 is small for statistical claims.
2. Two validated findings required curated test wiring or synthetic fix patches.
3. Generalization sweep (Basin → UUPS pool): **0 POTENTIAL** latent bugs; honest null.
4. Halmos 60s budget insufficient for some real-contract setups.
5. Not evaluated against ACToolBench's full 162-finding set.

**Future work**

- Scale to N=1000+ across Code4rena 2022–2025, all severity classes.
- Expand to arithmetic, reentrancy, oracle manipulation.
- Publish open benchmark: spec JSON + test + commits + verdict per finding.
- Combine with Slither: mined specs as high-precision regression tests for static-analysis false-negative gaps.
- Cross-language equivalence (BabelBench-style) and proof-search targets (Deductive Vericoding)—not implemented here.

---

## 8. Related work

- **ACToolBench** — Wu et al., *Have We Solved Access Control Vulnerability Detection in Smart Contracts?* ASE 2025. [Paper](https://daoyuan14.github.io/papers/ASE25_ACToolBench.pdf)
- **Halmos** — a16z crypto, SMT-based symbolic execution for Solidity. [GitHub](https://github.com/a16z/halmos)
- **Code4rena** — competitive audit platform; source of findings and commit metadata. [GitHub](https://github.com/code-423n4)
- **Solodit** — aggregated audit finding database (Cyfrin). [solodit.cyfrin.io](https://solodit.cyfrin.io)

---

## 9. Citation

If you use this benchmark or pipeline, please cite:

```bibtex
@misc{bugzy2026,
  author       = {Demiladepy},
  title        = {Bugzy: Mining Executable Security Specifications from Audit Findings},
  year         = {2026},
  howpublished = {\url{https://github.com/Demiladepy/bugreport}},
  note         = {SPS Hackathon submission; N=20 Code4rena access-control benchmark}
}
```

---

## 10. License and contact

- **Code:** See repository license file.
- **Corpus:** Finding text originates from public Code4rena disclosures; respect original contest terms.
- **Issues / reproduction bugs:** GitHub Issues on this repository.

---

*Last updated: May 2026. Metrics regenerated via `python -m src.benchmark report`. For the evaluation narrative, see [`RESULTS.md`](RESULTS.md).*
