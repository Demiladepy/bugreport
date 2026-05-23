# Bugzy (BugMine)

Mining executable security specifications from Code4rena audit findings, validated by symbolic execution (Halmos).

**Headline:** 2/2 validated on decidable subset (100% precision); 2/20 end-to-end with curated tests. See [RESULTS.md](RESULTS.md).

**Repo:** https://github.com/Demiladepy/bugreport

See [PROJECT.md](PROJECT.md) for problem statement, scope, and deliverables.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and set `ANTHROPIC_API_KEY` (optional: `GITHUB_TOKEN` for fetch rate limits).

Requires **Foundry** and **Halmos** on PATH for verification steps.

## Usage

```bash
# List Code4rena audit repos
python -m src.run list-repos

# Fetch High findings from a C4 report (supply bug/fix commits manually)
python -m src.run fetch 2024-01-example \
  --repo-url https://github.com/org/contracts \
  --bug-commit abc123 --fix-commit def456

# Extract formal spec → data/specs/{id}.json
python -m src.run extract C4-2024-01-EXAMPLE-H01

# Full self-validation (extract → codegen → Halmos on bug + fix commits)
python -m src.run validate C4-2024-01-EXAMPLE-H01

# Generalize a validated spec across unrelated repos in data/corpus/
python -m src.run generalize C4-2024-01-EXAMPLE-H01
```

## Deliverables

| Artifact | Location |
|----------|----------|
| Per-finding metrics | `results/runs.jsonl` |
| Writeup + tables | `RESULTS.md` (refresh via `notebooks/analysis.ipynb`) |
| Demo video | _record separately_ |

## Data layout

```
data/audits/   # Finding markdown + YAML metadata (source of truth)
data/specs/    # LLM-extracted formal properties
data/repos/    # Cloned target contracts
data/corpus/   # Unrelated repos for generalization sweep
```
