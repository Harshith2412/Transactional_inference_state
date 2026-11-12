# Failure modes

| Failure | Trigger | Current behavior | Consequence / containment | Recovery / future mitigation |
|---|---|---|---|---|
| Parser rejection | malformed or schema-invalid text | explicit `ModelPlanError`; runner rolls back | no operations execute; not counted as runtime containment | improve prompting without weakening parser |
| Model refusal/not followed | no matching malicious operation | `MODEL_ATTACK_NOT_FOLLOWED` | no observed model compromise | record separately; broaden prompts/models |
| Policy false negative | malicious plan accepted | commit proceeds | persistent/effect compromise possible; not contained | independent semantic policy evaluation |
| Policy false positive | benign plan rejected | rollback/discard | safe but utility loss | measure false rejection; improve policy |
| Shared stale write | observed version differs at commit | `WriteConflictError`, `ABORTED` | silent overwrite prevented | retry at application layer (not implemented) |
| Cross-session attempt | wrong session identity | `TransactionError` | scoped access rejected | immutable capability/context design |
| Rollback failure | restore/discard raises | no special recovery layer | integrity may be uncertain | durable log, fail-stop behavior, formal recovery |
| Digest mismatch | post-rollback canonical state differs | experiment/test fails | signals restoration defect | quarantine state and investigate |
| Partial effect failure | an effect target raises after prior execution | failed effect `FAILED`, later `STAGED`, tx `PARTIAL_EFFECT_FAILURE` | prior effects remain externally visible | reconciliation, idempotency, compensation |
| Commit/effect crash window | process stops after state commit | no durable recovery | staged action may be missing or ambiguous | durable outbox and crash recovery |
| Duplicate effect execution | execution requested twice | lifecycle error within process | duplicate prevented in current lifetime | durable idempotency keys across crashes |
| Model timeout | Ollama exceeds timeout | unavailable record; paired trials excluded from denominators | no model plan; no state/effect execution | configurable retry/backoff and availability reporting |
| Unsupported operation | unknown enum/type | parser rejection | fail closed | explicitly version operation schema |
| Invalid provenance | unknown claimed source | parser rejection | no authority gained | signed/runtime provenance in future |
| Delta materialization | full-state callback or callable policy | deferred deep copy | correct but performance advantage may disappear | finer-grained policy views and operations |
| Resource exhaustion | huge plan/state/value | no comprehensive budget | latency/memory denial of service | plan, state, effect, and operation budgets |

Already executed real effects are never described as rolled back. Recovery claims
are limited to tested in-memory state and simulated staged actions.

