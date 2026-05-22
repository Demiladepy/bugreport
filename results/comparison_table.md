# Bugzy vs ACToolBench — Methodology Comparison

ACToolBench (Daoyuan Wu et al., ASE 2025) evaluates **zero-shot access-control vulnerability detection** on Code4rena findings. Bugzy evaluates **spec extraction + self-validation + reuse** on the same class of findings. The tasks are related but not identical; this table states where comparison is fair and where it is not.

| Metric | ACToolBench (Slither) | ACToolBench (Mythril) | ACToolBench (LLM) | Bugzy (N=20 bulk run) |
|---|---|---|---|---|
| **Task** | Find AC bugs in contest code | Find AC bugs in contest code | Find AC bugs in contest code | Extract spec from known bug → Halmos test → validate on commits |
| **TP rate (bugs caught)** | Low (~8 TPs in evaluated set) | Very low (~4 TPs) | 53–75% on subset | **100% on decidable validated specs** (1/1 bulk; 2/2 pilot) |
| **FP rate** | Very high (389 FPs reported) | Moderate | Hallucination / false alarms | **0% on validated specs** (by construction: spec must fail bug + pass fix) |
| **End-to-end yield** | N/A (detection tool) | N/A | N/A | **5%** (1/20 unattended); **10%** including pilot Basin |
| **Avg time per finding** | Seconds (static analysis) | Minutes; **25.9% timeout** | Seconds–minutes per prompt | **~8.4 s** extract; **~47 s** avg verify attempt (bulk run) |
| **Halmos timeout (60s budget)** | N/A | N/A | N/A | **0/20** — failures are build/setup, not solver |
| **Decidability** | High (always returns) | Medium (timeouts common) | High (no proof obligations) | Low in bulk (13/20 vulnerable attempts; 1/20 full validate) |
| **Reusability across contracts** | No | No | No | **Yes** — validated spec → symbolic test applicable to N contracts (preliminary) |

## Per-stage funnel (Bugzy only)

| Stage | N=20 rate |
|---|---|
| Spec extraction | 20/20 (100%) |
| Test codegen | 18/18 non-curated (100%) |
| Vulnerable verify: FAIL (bug caught) | 2/20 (10%) |
| Fix verify: PASS (no false positive) | 1/20 (5%) |
| Self-validated (both legs) | 1/20 (5%) |

## Discussion

Slither, Mythril, and LLM-only auditors answer: *“Does this contract contain an access-control bug right now?”* They optimize recall on a fixed codebase at the cost of noise (Slither’s hundreds of false positives) or incompleteness (Mythril’s timeout rate). ACToolBench shows that even strong LLMs reach only ~53–75% true-positive rate—and cannot produce a durable artifact.

Bugzy inverts the problem. We assume the bug is **already documented** in a Code4rena report (human-audited ground truth). The pipeline extracts an executable property, checks it against vulnerable and fixed commits, and—if validated—obtains a **reusable Halmos test**. False positives from “did we find the bug?” become false positives from “did we extract the right spec?”—filtered by commit-grounded self-validation.

Our N=20 unattended benchmark shows extraction and codegen are solved at current LLM quality; **verify integration is not**. Two findings (Basin, Blackhole) produce counterexamples on vulnerable commits in bulk; only Blackhole completes full validation unattended. Pilot work confirms Basin validates with hand-tuned real-contract setup.

The publishable claim is not “Bugzy beats Slither on TP rate.” It is: **audit prose yields validated, reusable formal tests at non-zero rates**, with per-stage transparency on failure modes—a novel axis ACToolBench does not measure.
