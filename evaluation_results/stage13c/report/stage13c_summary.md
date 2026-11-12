# Stage 13C independent validator comparison

Validators propose inspectable actions; the unchanged transactional runtime enforces them. `DENY`, `QUARANTINE`, and `REVIEW` were frozen as security interventions before evaluation.

## Frozen held-out results

| Validator | Recall | FPR | F1 | Persistent compromise | Benign completion | Median validation |
|---|---:|---:|---:|---:|---:|---:|
| POLICY_V2_BASELINE | 8/20 (40.0%) | 0/20 (0.0%) | 0.571 | 12/20 | 20/20 | 51.3 µs |
| SEQUENCE_AWARE | 6/20 (30.0%) | 0/20 (0.0%) | 0.462 | 14/20 | 20/20 | 5.7 µs |
| PROVENANCE_AWARE | 20/20 (100.0%) | 10/20 (50.0%) | 0.800 | 0/20 | 10/20 | 5.1 µs |
| SEMANTIC_RULE | 10/20 (50.0%) | 0/20 (0.0%) | 0.667 | 10/20 | 20/20 | 5.8 µs |
| HYBRID_DETERMINISTIC | 20/20 (100.0%) | 10/20 (50.0%) | 0.800 | 0/20 | 10/20 | 69.7 µs |

PolicyV2 reproduces the Stage 13A development baseline at 9/20 and reaches 8/20 on held-out variants. Sequence reasoning independently reaches 6/20. The semantic validator reaches 10/20 with zero hard-benign false positives. Provenance and hybrid reach 20/20, but each intervenes on 10/20 hard-benign workflows whose quoted text has untrusted retrieved ancestry. Their 50% FPR makes them unsuitable as an unconditional default despite full recall.

Every intervention contained state/effects in this deterministic harness. Baseline false negatives left 12/20 persistent compromises and two simulated malicious effects; semantic left 10/20 and two effects; provenance/hybrid left none but cut benign completion to 10/20.

## Flagship

The preselected semantic-poison case is allowed by PolicyV2 and sequence validation, quarantined by provenance, denied by semantic rules, and denied by hybrid composition. Reasons, confidence, persistence, effects, and latency are stored in `heldout/flagship.json`.

## Separation and freezing

Ground-truth labels and attack-family names are evaluator-only. Validator evidence contains operations, authoritative sources, scope, dependencies, order, and gap state. Validator fingerprints and held-out corpus hash `186dd355060a46ae9c83b7da0e8f2c484d9e4ab9be767ba317ebb1be9f79ddc3` were recorded before the final held-out artifact run. No post-held-out tuning was performed.

Optional ML and LLM judge validators were not added to headline metrics: ML would introduce an evaluation dependency, and the LLM judge remains unavailable/advisory. Four saved valid Stage 13A Llama plans are reported only as supporting evidence.

## Boundary

Trusted mechanism remains 13 modules / 3087 LOC with zero trusted-core growth and zero third-party core dependencies. Validator/evaluation code is 204 non-comment LOC above the frozen transaction mechanisms.
