# Transactional external effects

Local rollback cannot reverse an email or other real-world action. The prototype
therefore models requests as `PendingEffect` values containing effect,
transaction/session IDs, type, operation, copied arguments, sequence, status,
and optional error. Statuses are `REQUESTED`, `STAGED`, `EXECUTED`, `DISCARDED`,
and `FAILED`.

`TransactionalTools.send_email` can stage but cannot directly call
`FakeEmailService`. `EffectManager` enforces ownership, deterministic sequence,
and at-most-once execution within the process:

```text
request → stage → validate → commit → execute
request → stage → reject   → rollback → discard
```

Concurrent transactions own separate effect sets. Rolling back A neither
executes nor discards B's effects. Executed effects cannot be discarded or run
twice.

Partial failure is explicit: if effect 1 executes, effect 2 fails, and effect 3
has not run, their states remain `EXECUTED`, `FAILED`, and `STAGED`; the
transaction becomes `PARTIAL_EFFECT_FAILURE`. The system does not claim effect
1 was rolled back. Internal state has already committed.

The fake service is deterministic and in-memory. There is no durable outbox,
idempotency across crashes, retry/reconciliation policy, or protection against
the crash window between internal commit and effect execution. No real email or
filesystem service is integrated.
