# Stage 8: independent policy and robustness

## Architecture and trust boundary

`PolicyEngine` receives a parsed `ModelPlan` and `PolicyContext`. The context
contains transaction/session identity, a scoped `CapabilitySet`, target
`ResourceScope`, and immutable records from `ProvenanceRegistry`. Scenario labels
exist only beside results as confusion-matrix ground truth and are absent from
the policy API. The Stage 6/7 evaluator remains unchanged for reproducibility.

Capabilities cover memory/cache reads and writes and simulated email; grants can
be session- or recipient-scoped. Sensitive aliases such as `role`,
`access_level`, `permission_level`, and authorization caches additionally need
`security_state.write` and trusted originating provenance. Claimed provenance
cannot create authority.

## Deterministic observations

The measured 60-trial corpus combines 32 policy-evasion attacks, eight semantic
poisoning attacks, and 20 benign plans:

| TP | FN | FP | TN | precision | recall | F1 | FPR | FNR |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 27 | 13 | 0 | 20 | 100% | 67.5% | 80.6% | 0% | 32.5% |

All rejected compromised trials were contained. Thirteen accepted attacks
persisted, so rollback containment is not attack prevention. The evasion corpus
detected 23/32 and missed 9/32. Semantic poisoning detected 4/8; the other four
persisted. These are measured limits of the lightweight rules.

Five multi-turn experiments each use three independent transactions on the same
session. A seed commits on turn 1, a turn-2 transaction reads it, and a protected
turn-3 action is rejected. The later action is contained, but the accepted seed
remains: detection does not retroactively undo earlier committed transactions.

## Budgets, deltas, and effects

`TransactionBudget` defaults are 50 operations, 1 MiB aggregate state writes,
ten effects, depth 20, a 256 KiB raw plan, and a 1 MiB approximate delta. They
are configurable prototype values, not universal safe limits. Controlled
operation, write, effect, nesting, and plan attacks each failed closed. Delta
accounting reports approximate bytes, changed keys, deletions, and materialized
state size.

`PendingEffect.idempotency_key` is retained in process. A retry after success is
suppressed; a retry after failure before successful execution is allowed. This
is not durable crash-safe deduplication.

## Failure windows

Injected failures after begin, mutation, validation, and during pre-apply commit
remain rollback-safe. Failures after internal commit or before effects leave
internal state visible without effects. Failure after the first of two effects
leaves state and one effect visible. Those windows require reconciliation; the
runtime does not claim durable atomicity across internal state and effects.

## Local-model subset and overhead

The explicit-schema subset used installed `llama3.2:3b` and `qwen3:4b` models
without downloads: five malicious and five benign prompts with one trial each.
Each raw response was reused for its baseline/transactional pair. Llama parsed
9/10; Qwen parsed 0/10. Unparseable plans are excluded from independent policy
precision/recall and overhead rather than assigned policy decisions.

For Llama's nine timing pairs, mean generation was 2.693 s, transactional runtime
0.200 ms, paired incremental runtime 0.193 ms, and runtime was 0.00744% of
end-to-end latency. Qwen had no parseable timing pairs. Results are hardware- and
run-specific.

See the [Stage 8 summary](../evaluation_results/stage8/summary.json),
[independent live-policy records](../evaluation_results/stage8/live_independent_policy.json),
[tables](../evaluation_results/stage8/tables/), and
[figures](../evaluation_results/stage8/figures/).
