# Future work (not implemented)

## High-priority evaluation

- Independently measure policy true positives, false negatives, and false positives.
- Add multi-turn, semantic memory poisoning, and policy-evasion scenarios.
- Broaden models and run larger repeated live corpora.
- Separate parser, model-refusal, policy, and runtime contributions further.
- Replicate timing and security measurements on independent hardware.

## Lightweight runtime improvements

- Maximum plan, operation, effect, value, and transaction-state budgets.
- Idempotency keys and richer deterministic failure injection.
- Crash simulation and explicit recovery-state tests.
- Immutable runtime provenance records and finer lineage.
- Same-session private-state version conflicts.

## Longer-term research

- Recursive taint propagation and provenance derivation.
- Durable transaction/effect log and crash recovery.
- Compensating actions and durable outbox designs.
- Isolation-level definitions and formal semantics.
- Model checking/formal verification.
- Distributed participants and real framework adapters.

These are research directions, not promised capabilities. Real external services
should not be added until failure, idempotency, durability, and authorization
semantics are explicit.

