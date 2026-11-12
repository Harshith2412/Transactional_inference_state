# Redis transactional participant results

Real localhost Redis 7 evaluation, 50 measured transactions.

- Accepted RMW: Redis `10 → 11`; `10` remained externally visible before commit.
- Rejected RMW: Redis remained `10`.
- Read-your-writes: transaction observed `B`; Redis exposed `A` until commit.
- Isolation: T2 observed committed `A`, not T1's buffered `B`.
- Conflict: external `A → C` won; stale T1 aborted and did not overwrite `C`.
- Commit failure: explicit `partially_committed`, never reported as success.
- Provenance: runtime-issued `TOOL_RESULT` source attached to derived state.

See `scenarios.json`, `performance.json`, `comparison.json`, and `summary.json` for raw evidence and [`docs/52_redis_transactional_participant_evaluation.md`](../../docs/52_redis_transactional_participant_evaluation.md) for interpretation and limitations.
