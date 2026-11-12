# Transaction semantics

`TransactionManager` generates deterministic per-manager IDs such as
`txn-000001`. In session-managed mode, each `Transaction` records ID, session,
status, snapshot/strategy context, local state when materialized, shared read
versions, tentative shared writes, and validation result.

Lifecycle states are `ACTIVE`, `VALIDATED`, `REJECTED`, `COMMITTED`,
`ROLLED_BACK`, `ABORTED`, and `PARTIAL_EFFECT_FAILURE`.

- `begin(session_id)` creates strategy context and an audit event.
- private reads/writes/deletes require matching transaction/session ownership.
- `validate(tx)` invokes deterministic fixed or callable policy.
- `commit(tx)` requires `VALIDATED`, checks shared conflicts, publishes private
  state, records commit, then executes staged effects.
- `rollback(tx)` restores the Stage 1 state or discards concurrent local state
  and staged effects without modifying other committed sessions.

Closed transactions reject commit, rollback, validate, mutate, or effect
staging. Commit without validation and commit after rejection raise
`TransactionError`. Shared conflict changes status to `ABORTED`. An effect
failure after internal commit changes status to `PARTIAL_EFFECT_FAILURE`.

Stage 1 compatibility mode accepts a direct `InferenceState`, permits one active
transaction, snapshots it, preserves object identity on restore, and requires
`FullCopyStrategy`.

Tested invariants: rejected private mutations do not persist; accepted ones do;
rollback is structurally exact; session ownership is enforced; dirty writes are
invisible; stale shared writes do not silently overwrite; lifecycle misuse
raises explicit errors.

