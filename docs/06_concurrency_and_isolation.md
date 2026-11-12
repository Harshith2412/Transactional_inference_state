# Concurrency and isolation

Session-managed mode allows multiple individually addressed transactions. Each
starts from its owning session and never exposes its local state through a
different session identity. Rollback discards only that transaction's local
context, so it cannot undo a different session's commit.

`SharedState` is an explicit application-level key/value store whose entries
carry integer versions. A transaction records observed versions in its read set
and tentative values in its write set. Reads consult the transaction's own
write first, otherwise committed state. Consequently uncommitted writes are not
dirty-readable.

Dirty-read experiment:

```text
committed role = user
Tx-A writes role = admin (tentative)
Tx-B reads role = user
```

For optimistic conflict detection, two transactions may read version N. After
Tx-A commits version N+1, Tx-B's attempted write based on N raises
`WriteConflictError`, records conflict/rollback events, and becomes `ABORTED`.
There is no last-write-wins fallback.

Limitations: private state has no same-session version-conflict detection;
execution is not thread-safe; isolation levels are not formally specified; and
shared state is in-memory and non-durable.

