# Threat model

## Attacker capabilities

The evaluation represents malicious user prompts, indirect injections,
retrieved content, previously stored untrusted memory, tool-result poisoning,
cache and persistent-memory poisoning, malformed plans, provenance spoofing,
cross-session references, and requests for simulated email exfiltration. The
model may follow unsafe instructions and propose matching operations.

## Trusted computing base

- `TransactionManager`, `SessionManager`, snapshot strategies
- `SharedState` version/conflict logic
- strict plan parser and `OperationExecutor`
- `PolicyValidator`
- `EffectManager` and `TransactionalTools`
- canonical integrity digest
- runtime-observed provenance assignment

## Untrusted data

User prompts, retrieved content, model text, proposed operations, tool results,
model-claimed provenance, and future-session instructions embedded in data are
untrusted. Provenance strings emitted by a model grant no authority.

## Assumptions and exclusions

The attacker does not modify trusted Python code, bypass object capabilities,
tamper with committed state out-of-band, compromise the interpreter/OS, or alter
result files. The prototype has no real email, network tool, database, durable
log, process isolation, or distributed participants. Denial of service and
resource exhaustion are recognized but not comprehensively controlled.

If trusted policy accepts a malicious plan, transactional execution commits it;
rollback is containment after rejection, not a substitute for policy quality.

