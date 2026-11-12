# Stage 13D — Durable Journal and Crash Recovery

Stage 13D adds one opt-in trusted runtime module beneath the frozen policy and
validator layers. It is a local recovery experiment, not distributed atomicity.

## Journal format and durability

The journal is newline-delimited canonical JSON. Every record includes format
version, global sequence number, transaction and session IDs, type, payload,
previous hash, and record hash. SHA-256 chains each canonical record to its
predecessor. This detects modification, deletion, and reordering in observed
history; it provides integrity, not authentication.

Each append writes, flushes, and—when configured—calls `os.fsync`. Claims are
limited to local-filesystem semantics. Benchmarks expose buffered and per-record
fsync modes.

## Ordering and recovery state machine

```text
TX_BEGIN → tentative records → VALIDATION_DECISION → PREPARE_COMMIT
         → STATE_COMMITTED → effect attempts/receipts → TX_COMPLETE
```

Tentative state, provenance, and lineage become visible only with a durable
`STATE_COMMITTED` record. Before that point recovery classifies the transaction
as `INCOMPLETE_UNCOMMITTED` or `PREPARED` and discards its tentative projection.
Afterward it retains state and classifies effects as pending, executed, or
outcome-unknown. Repeated recovery rebuilds keyed projections and is idempotent.

Quarantine and unresolved review entries are durable trusted-control state,
never ordinary session state. Review tokens are restored unchanged and are not
automatically resolved.

## Effects, integrity, and limitations

Every effect has an idempotency key. A durable execution receipt suppresses
replay. A committed, never-attempted effect may replay. If execution may have
occurred without a receipt, recovery reports `EFFECT_OUTCOME_UNKNOWN` rather
than blindly retrying. A target-side lookup can resolve this boundary; the local
journal alone cannot.

An incomplete final line is truncated after prior records verify. Malformed
middle records and hash mismatches stop recovery with `JOURNAL_CORRUPTION`;
unsupported versions are rejected. The chain is not authenticated.

Artifacts report 100, 1,000, and 10,000-record replay plus disabled, buffered,
and fsynced transaction latency. Checkpointing is deferred, so replay is linear.
Other limitations include no multiprocess writer lock, JSON-compatible payloads
only, local filesystem failure semantics, and no atomicity with real services.

Results, ten tables, and eight SVG figures are in
`evaluation_results/stage13d/`.
