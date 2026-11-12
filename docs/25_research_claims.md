# Research claims

## Supported by current evidence

- Rejected transactions restored tested private state structurally and by digest.
- Tested staged effects did not execute on rollback.
- Tested transaction-local shared writes were not dirty-readable.
- Tested stale shared writes raised conflicts instead of silently overwriting.
- Delta reduced measured latency in most matrix cells; two dense-cell crossovers
  were observed.
- Runtime-observed provenance overrode model claims in tested spoof scenarios.
- Transactional mode prevented persistent/effect compromise in the evaluated
  deterministic corpus conditional on its scenario-encoded rejection policy.

## Preliminary

- Containment appears separable from model behavior because the same runtime
  contained the few parseable compromised live-model trials observed.
- Runtime overhead may be small relative to local model inference.
- Delta may scale favorably for sparse key-level mutation.

These remain preliminary because model/corpus/environment samples are limited.

## Not supported

- Universal prompt-injection or state-poisoning protection.
- Complete semantic policy detection or full taint tracking.
- Model-independent live policy effectiveness: Stage 10 produced no evaluable
  compromised live plans, and Qwen produced no parseable plans in the bounded matrix.
- Stage 11 provides meaningful live policy evidence for qualified Llama only;
  Qwen remained interface-unreliable, so cross-model independence is not claimed.
- Production-grade availability, crash safety, or durability.
- Arbitrary real-world effect rollback.
- Distributed atomicity or thread-safe isolation.
- Production deployment readiness or formal security proof.

“100% containment” means all eligible compromised trials in a stated sample left
no measured prohibited persistence/effect. It does not mean all attacks were
recognized, all models were compromised, or future attacks are guaranteed safe.
