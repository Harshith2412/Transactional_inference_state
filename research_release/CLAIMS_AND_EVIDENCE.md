# Claims and evidence

| Claim | Evidence | Experiment | Result | Scope | Limitation |
|---|---|---|---|---|---|
| Rejected transactions restore tested internal state. | Structural equality and canonical SHA-256 state digests. | Rollback, nested mutation, failure injection, and forced-rejection replay tests. | Forced rejection restored 75/75 compromised plans; the suite passes rollback invariants. | Selected JSON-compatible in-memory `InferenceState` fields. | Not arbitrary machine, process, model-weight, or OS state. |
| Accepted transactions retain mutations. | Post-commit state assertions and lifecycle tests. | Deterministic runtime tests. | Committed writes remain visible and closed transactions reject mutation. | In-process runtime. | No durability or crash recovery. |
| Private sessions are isolated and shared conflicts are detected. | Cross-session tests, read/write sets, versions, and conflict events. | Stage 2 concurrency experiments. | Rollback in A leaves B intact; stale shared writes abort. | Explicit session state and versioned shared cache. | Not thread-safe or distributed; private same-session conflicts are not version checked. |
| Rejected staged effects do not execute. | Fake service call count and effect status. | Rejected-effect and forced-rejection experiments. | 0/75 transactional external effects under forced rejection versus 24/75 immediate baseline. | Simulated effects staged through the provided effect manager. | Does not roll back arbitrary or already-executed external effects. |
| Full-copy and delta strategies preserve tested rollback integrity. | State digest comparisons across mutation ratios and sizes. | Snapshot matrix. | Both strategies pass integrity checks in the tested workloads. | Key-level, in-memory state. | Timing is local; delta can materialize full state for some operations. |
| Policy detection and transactional containment are separable. | Confusion matrices plus forced-rejection replay. | Stage 10 and Stage 11. | Stage 10 V2 recall 70.0%; live V2 recall 69/75, while rejected live plans were contained 69/69. | Frozen corpora and evaluable Llama plans. | Containment is conditional on rejection; six live false negatives persisted. |
| PolicyV2 improves recall over PolicyV1 but introduces false rejection. | Frozen-policy paired confusion matrices. | Stage 10 held-out evaluation. | V1: 35% recall, 0% FPR. V2: 70% recall, 12.5% FPR. | 100 malicious and 80 hard-benign handcrafted scenarios. | Corpus is finite and evaluation-designed. |
| The qualified live model produced enough valid plans for policy evaluation. | Raw and normalized parse records. | Stage 11 interface gate and full run. | Llama: 128/150 valid overall, with 75 malicious and 53 benign evaluable plans. | `llama3.2:3b` in the tested local setup. | Qwen failed qualification; live generations are variable. |
| PolicyV2 detected most evaluable compromised Llama plans, not all. | Trial-level policy results and Wilson interval. | Stage 11 live evaluation. | 69/75 (92.0%, 95% CI 83.6%–96.3%); persistent compromise 6/75. | Evaluable compromised plans from one qualified model. | Conditional denominator and six indirect-authorization misses. |
| Enforcement was a small measured portion of local generation latency. | Compatible phase timings. | Stage 11 performance analysis. | Median enforcement 0.093 ms; P95 0.182 ms; median generation 2.298 s; mean fraction 0.00461%. | 84 compatible local timing records. | Hardware-, model-, load-, and instrumentation-dependent; 44 fixture timing errors were excluded. |
| The core is dependency-light. | Source/packaging complexity audit. | Stage 10 complexity report. | Seven trusted modules, 1,210 Python LOC, zero third-party core runtime dependencies. | Frozen trusted-core definition. | Excludes evaluation/reporting code, pytest, Matplotlib, and optional Ollama. |

## Documentation audit

The audit searched the README, trust-boundary document, and `docs/` for absolute
security, universal-overhead, and arbitrary-rollback language. Existing Stage 9,
Stage 10, Stage 11, claims, and limitations documents already qualify their 100%
figures. The top-level README was rewritten to put Stage 10 and Stage 11
denominators beside the containment result and to state the simulated-effect and
in-memory scope. No experimental result was altered.
