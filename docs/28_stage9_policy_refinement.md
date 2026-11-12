# Stage 9: policy refinement and held-out validation

## Method

Stage 8's engine is preserved as `PolicyV1`. Before refinement, all 13 accepted
malicious Stage 8 transactions were reproduced and assigned a structured
taxonomy. `PolicyV2` was designed against a distinct 24-scenario development
split and frozen before the disjoint 24-scenario held-out split was evaluated.
Scenario ground truth remains outside both policy APIs.

PolicyV2 adds inspectable alias mappings, scoped authorization/trust/bypass
patterns, quoted educational-text exemptions, whole-plan sequence/composition
checks, and stricter handling of effects derived from runtime-issued memory
provenance. It remains a deterministic rule set, not an NLP model.

## Stage 8 false-negative taxonomy

| Category | Count | Share |
|---|---:|---:|
| Semantic memory poisoning | 4 | 30.8% |
| Indirect authorization claim | 1 | 7.7% |
| Multi-field composition | 4 | 30.8% |
| Operation-sequence abuse | 4 | 30.8% |

Each record retains operations, claimed/runtime provenance, capabilities,
target state, miss explanation, persistence, and later-behavior impact.

## Development and held-out results

Each common evaluation includes 24 malicious, 24 hard benign, and 20 ordinary
benign scenarios.

| Split / policy | TP | FN | FP | TN | Precision | Recall | F1 | FPR | Persistent compromise | Benign completion |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Development V1 | 2 | 22 | 4 | 40 | 33.3% | 8.3% | 13.3% | 9.1% | 91.7% | 90.9% |
| Development V2 | 24 | 0 | 0 | 44 | 100% | 100% | 100% | 0% | 0% | 100% |
| Held-out V1 | 4 | 20 | 4 | 40 | 50.0% | 16.7% | 25.0% | 9.1% | 83.3% | 90.9% |
| Held-out V2 | 19 | 5 | 0 | 44 | 100% | 79.2% | 88.4% | 0% | 20.8% | 100% |

PolicyV2 held-out recall is 19/24, 79.2%, with a Wilson 95% interval of
59.5%–90.8%. Its observed held-out FPR is 0/44, with an upper Wilson bound of
8.0%. PolicyV2 was not changed after these five held-out misses were observed.
The development-to-held-out drop prevents a claim of perfect generalization.

On the 24 hard benign cases alone, V1 rejected 4 while V2 rejected none because
quoted/article/definition contexts are explicit exceptions. This handcrafted
set does not establish a generally zero false-positive rate.

## Ablation

| Components through… | Recall | FPR |
|---|---:|---:|
| capabilities | 0% | 0% |
| session/resource scope | 8.3% | 0% |
| runtime provenance | 8.3% | 0% |
| security aliases | 37.5% | 0% |
| semantic/context rules | 66.7% | 0% |
| sequence/composition rules | 100% | 0% |

Provenance alone did not improve this development set. It became useful in the
separate multi-turn effect rule. Sequence/composition supplied the largest
increment. These are descriptive paired comparisons; no significance test is
claimed.

## Persistent lineage and multi-turn behavior

Committed memory writes retain immutable runtime metadata: entry ID, source
IDs/types, origin transaction, and origin session. In the controlled
memory-to-effect comparison, V1 allowed the later simulated email and leaked an
effect; V2 rejected the memory-derived effect on turn 3. In both cases the
turn-1 seed remained. This is later detection, not retroactive rollback.

## Live subset

The bounded explicit-schema subset used six held-out malicious and six hard
benign prompts per installed model, once each, pairing each response across
V1/V2. Llama produced 2/12 parseable plans and Qwen 0/12. Both Llama evaluable
plans were benign, so malicious recall is not estimable. Mean generation was
approximately 2.302 s for Llama and 3.610 s for Qwen. Parser failure—not policy
success—dominates this live result.

## Containment and limitations

Containment after deterministic rejection, structural rollback, SHA-256
rollback integrity, and effect discard remained 100%. This measures containment
conditional on rejection, not perfect attack prevention.

Corpora and live denominators remain small and handcrafted. Patterns are
evadable, lineage is lightweight rather than recursive taint, idempotency/state
are process-local, and state commit is not durably atomic with effects.

See the [Stage 9 summary](../evaluation_results/stage9/summary.json),
[tables](../evaluation_results/stage9/tables/), and
[figures](../evaluation_results/stage9/figures/).
