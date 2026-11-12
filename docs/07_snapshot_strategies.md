# Snapshot strategies and integrity

## FullCopyStrategy

At begin, the complete private `InferenceState` is eagerly deep-copied. Reads
and mutations target that copy. Commit restores the copy into the committed
state; rollback discards it (or restores the Stage 1 snapshot). Begin and commit
cost scale with copied state.

## DeltaStrategy

Begin creates a lightweight `DeltaContext` referencing committed base state.
Key-level replacements and deletes are stored per field. Reads return the
transaction's replacement when present, reject deleted keys, otherwise
deep-copy the committed value. This copy-on-read/write behavior prevents nested
dict/list aliasing. Commit applies the tracked delta; rollback discards it.

Requesting `transaction_state()` or using an arbitrary mutation callback lazily
materializes a full deep copy. Callable policies also require materialization;
fixed policies do not. Dense mutations, materialization, and key-container work
can remove Delta's advantage.

## Integrity digest

`canonical_state_bytes` serializes dataclass state as sorted, compact JSON;
`state_digest` computes SHA-256. Experiments require both structural equality
and matching pre/post rollback digests. Digest equality supplements rather than
replaces semantic equality. Values must currently be JSON-compatible.

Measured matrix results are in [performance analysis](15_performance_analysis.md).

