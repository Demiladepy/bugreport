# BugMine

**Mining executable security specifications from natural-language audit findings.**

## Problem

Smart contract audits produce hundreds of detailed bug reports per year. Each report contains an implicit **specification** — the property the contract violated — written in English. Today these specs are read once, fixed, and forgotten. They never become reusable security tests for other contracts.

AI is now writing more code than auditors can audit. We need a way to bootstrap formal specifications from the work that's already been done, then re-apply those specs to new code automatically.

## What we're building

A pipeline that:

1. **Ingests** audit findings from **Solodit** (hand-curated seed corpus with `vulnerable commit → fix commit` linkage)
2. **Extracts** the underlying formal property using an LLM (Claude)
3. **Generates** a Halmos property test in Solidity
4. **Self-validates** the spec by running it against both commits:
   - Must FAIL on the vulnerable commit (catches the bug)
   - Must PASS on the fix commit (doesn't catch noise)
5. **Generalizes** validated specs by running them against unrelated contracts in the same ecosystem to find latent similar bugs

## Scope

- **Bug categories (in priority order):**
  1. Access control (missing modifier, role check bypass) — primary
  2. State machine violations (function called in wrong state) — stretch
- **Source:** [Solodit](https://solodit.cyfrin.io) — Code4rena findings, High/Critical severity, Access Control category (primary). Per-contest `code-423n4/*-findings` repos as fallback. The consolidated `code-423n4/reports` repo is deprecated.
- **Verification tool:** Halmos (SMT-based symbolic execution for Solidity)
- **LLM:** Claude Sonnet via Anthropic API
- **Target corpus size:** 20–30 findings validated, 100+ contracts for generalization sweep

## Tracks addressed

- Track 1 (Spec Elicitation): extracting specs from audit prose
- Track 2 (Spec Validation): self-validation against ground-truth commit history
- Track 4 (Adversarial Robustness): mined specs as adversarial test suite for new code

## Success criteria

**Minimum viable:** Pipeline runs end-to-end on 5 findings, ≥3 specs self-validate correctly.
**Good:** ≥20 findings, ≥15 self-validate, ≥1 generalizes (finds a similar bug in unrelated code).
**Hackathon-winning:** ≥30 findings, ≥20 self-validate, ≥3 generalize with reproducible counterexamples + writeup explaining what extraction-failure modes exist.

## Non-goals

- Not building a UI
- Not building a vericoding (code-generation) loop
- Not handling Medium/Low severity findings
- Not handling Lean/Coq — Solidity + Halmos only

## Architecture

```
data/
  findings_seed.jsonl  # Hand-picked Solodit findings (one JSON object per line)
  audits/              # Normalized finding markdown + metadata
  repos/               # Cloned protocol repos at vulnerable/fix commits
  specs/               # LLM-extracted formal properties (JSON)

src/
  fetch.py             # Ingest from Solodit URL or findings_seed.jsonl
  extract.py           # LLM extraction: finding → formal spec
  codegen.py           # Spec → Halmos test contract
  verify.py            # Run Halmos against a given commit
  validate.py          # Self-validation loop
  generalize.py        # Apply validated specs to other repos

results/
  runs.jsonl           # One line per finding: spec, validation, generalization

notebooks/
  analysis.ipynb       # Final write-up + plots
```

**`findings_seed.jsonl` schema** (one object per line):

```json
{"id": "...", "title": "...", "source_url": "...", "vulnerable_commit": "...", "fix_commit": "...", "repo_url": "...", "affected_file": "...", "category": "access_control", "raw_markdown": "..."}
```

### Pipeline flow

```
Solodit / findings_seed.jsonl
        │
        ▼
   fetch.py    ──►  data/audits/*.md + clone repo at bug/fix commits
        │
        ▼
   extract.py  ──►  data/specs/{id}.json
        │
        ▼
   codegen.py  ──►  HalmosTest.sol in target repo
        │
        ▼
   verify.py   ──►  HalmosResult (pass / fail / timeout / error)
        │
        ▼
  validate.py  ──►  fail on bug commit, pass on fix commit
        │
        ▼
 generalize.py ──►  sweep unrelated contracts
        │
        ▼
  results/runs.jsonl  +  RESULTS.md  +  notebooks/analysis.ipynb
```

### Module responsibilities

| Module | Input | Output |
|--------|-------|--------|
| `fetch.py` | Solodit URL or seed JSONL | Curated audit markdown + cloned repo |
| `extract.py` | Audit markdown | Formal spec JSON in `data/specs/` |
| `codegen.py` | Extracted spec | Solidity Halmos test file |
| `verify.py` | Repo path, commit, test file | Parsed Halmos stdout |
| `validate.py` | Finding ID | Self-validation verdict + logs |
| `generalize.py` | Validated spec + corpus | Cross-contract pass/fail report |

### External dependencies

- **Solodit** — primary finding source ([solodit.cyfrin.io](https://solodit.cyfrin.io)); API auth TBD (`SOLODIT_API_KEY`)
- **Anthropic API** — Claude Sonnet for spec extraction and codegen
- **GitHub API** — clone protocol repos, optional token for rate limits (`GITHUB_TOKEN`)
- **Foundry** — build/test harness for target repos
- **Halmos** — symbolic execution (`halmos` CLI)
- **Git** — checkout vulnerable and fix commits per finding

## Output

1. The pipeline code (this repo)
2. A `results/runs.jsonl` with per-finding metrics
3. A `RESULTS.md` writeup with:
   - Extraction success rate (specs that compiled vs failed)
   - Self-validation rate (specs that correctly distinguished bug from fix)
   - Generalization findings (any latent bugs detected in new code)
   - Honest limitations + failure mode analysis
4. A 3-minute demo video showing the pipeline end-to-end on a known finding

## What we are NOT trying to prove

- We are NOT claiming "AI can audit smart contracts"
- We are NOT claiming our specs are complete or sound
- We ARE claiming: human-written audits contain extractable, validatable specifications, and this is a useful primitive for AI-era code verification.

## Fellowship pitch (if asked)

> "We showed extraction-and-validation works on access control findings. For 4 months: expand to all severity classes, all major audit firms (Spearbit, OpenZeppelin), build a public benchmark dataset of validated specs, and integrate into CI workflows so every PR is auto-checked against the mined spec database."
