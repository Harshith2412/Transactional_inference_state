# Consolidated limitations

## Evaluation

- Corpora are handcrafted, finite, and not representative of all attacks.
- The Stage 8 independent policy is intentionally shallow: configurable aliases
  and regular expressions miss distributed and novel semantic intent.
- Only two local models were measured; some denominators are very small.
- Stage 10's three-mode live matrix used only four generations per model/mode;
  no malicious plan was evaluable, so live policy recall remains N/A.
- Prompting and strict-parser behavior strongly affect observed utility and compromise.
- Live outputs vary; one timed-out generation was excluded from denominators.
- Timing is hardware, load, interpreter, allocator, and cache sensitive.
- `tracemalloc` is not RSS and may omit important native/shared memory.

## Security model

- Provenance records are immutable but not cryptographic or recursive taint lineage.
- The trusted Python process, parser, policy, and managers are assumed uncompromised.
- There is no formal semantics, proof, model checking, or production hardening.
- Resource/plan budgets are approximate in-process prototype defenses.

## Runtime

- State is in-memory, single-process, non-durable, and not thread-safe.
- There is no crash recovery or distributed transaction protocol.
- Private same-session conflicts are not version-checked.
- Delta tracking is key-level; arbitrary callbacks and callable policies can force
  lazy full materialization.
- Canonical digest assumes JSON-compatible values.

## Effects and integrations

- External effects are simulated; no real email/network/database is tested.
- Internal commit precedes effect execution, leaving a crash window.
- Partial effects require reconciliation. In-process idempotency suppresses
  duplicate success, but there is no durable outbox, cross-crash deduplication,
  or compensation.
- Optional Ollama is localhost-only and lacks streaming/retry controls.

The generated [limitations report](../evaluation_results/report/limitations.md)
is preserved; this chapter consolidates it with runtime-specific limits.
