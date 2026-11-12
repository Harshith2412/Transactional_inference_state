# Redis transactional participant evaluation

## Scope and environment

This evaluation exercises the existing Redis adapter without adding features. The primary run used a disposable Redis 7 Alpine container exposed only on localhost, database 15, through the standard-library RESP2 transport. Performance results use 50 transactions. The container and evaluation keys were removed after the run.

Raw, machine-readable results are under [`evaluation_results/redis_transactional_participant/`](../evaluation_results/redis_transactional_participant/):

- `scenarios.json`
- `performance.json`
- `comparison.json`
- `summary.json`

This is an API-mediated participant experiment, not a distributed transaction. Redis was not copied into `InferenceState`, and the result does not establish transaction support for SQL, MCP, arbitrary databases, or other services.

## Scenario results

| Scenario | Observation | Result |
|---|---|---|
| Accepted read-modify-write | GET `10`; derived/buffered `11`; Redis before commit `10`; Redis after commit `11` | PASS, `committed` |
| Rejected read-modify-write | Proposed `11`; buffer discarded | PASS, Redis remained `10`, `rolled_back` |
| Read-your-writes | First GET `A`; buffered SET `B`; second GET `B` from write set | PASS, external Redis remained `A` until commit and then became `B` |
| Cross-transaction isolation | T1 buffered `B`; T2 read the same key | PASS, T2 and Redis observed committed `A` |
| External conflict | T1 observed `A`; external writer committed `C`; T1 attempted `B` | PASS, conflict detected, T1 `rolled_back`, Redis remained `C` |
| Redis commit failure | Local commit completed; injected transport failure occurred before a known Redis response | Negative result surfaced correctly: `partially_committed`, not successful; Redis oracle remained `A`, outcome conservatively classified `UNKNOWN` |
| Provenance | Redis GET fed local memory and a derived Redis SET | PASS, runtime-issued `TOOL_RESULT` provenance retained transaction/session origin and was attached to both derived writes |

## Exact read-modify-write path

```text
Redis GET counter ───────────────▶ b"10"
       │
       ├─ issue runtime TOOL_RESULT provenance
       ▼
trusted derivation int(10) + 1 ─▶ b"11"
       │
       ├─ TransactionManager.write_private(... provenance_ids=...)
       └─ RedisTransactionalParticipant.set(... provenance_ids=...)
                                              │
                                    buffered only; Redis is still 10
                                              │
                    validation accepts ───────┤
                                              ▼
                       local commit → Redis compare-and-apply → Redis is 11
```

The Redis read was copied only as an explicitly selected transaction-local application value. The Redis keyspace and server state were not snapshotted into `InferenceState`.

## Performance

All values are localhost measurements from this run and are hardware/environment dependent.

| Operation | Samples | Median | p95 |
|---|---:|---:|---:|
| Redis GET + read-set/provenance | 50 | 1.427 ms | 2.512 ms |
| Redis buffered SET | 50 | 0.0136 ms | 0.0178 ms |
| Redis coordinated commit | 25 | 2.970 ms | 3.914 ms |
| Redis rollback/buffer discard | 25 | 0.0116 ms | 0.0163 ms |
| Redis conflict abort | 50 | 1.152 ms | 2.501 ms |
| `InferenceState` read | 50 | 0.00444 ms | 0.00796 ms |
| `InferenceState` write | 50 | 0.0103 ms | 0.0183 ms |
| `InferenceState` commit | 25 | 0.0256 ms | 0.0453 ms |
| `InferenceState` rollback | 25 | 0.00458 ms | 0.00796 ms |

Redis read/commit latency is dominated by localhost protocol round trips and the preflight plus atomic compare-and-apply. Buffered writes and rollback remain local and are correspondingly much cheaper.

## Mechanism comparison

| Property | Application `InferenceState` | Redis API participant | CRIU checkpoint participant |
|---|---|---|---|
| Protected state | Selected Python dataclass fields | Selected Redis keys | Eligible external process memory/execution state |
| Speculation | Full copy, delta, or COW | Read cache plus buffered SET/DELETE | External process mutates after checkpoint |
| Read source | In-process application value | Redis GET or transaction write set | Participant service API |
| Commit | Copy/apply local overlay | Local commit followed by Redis compare-and-apply | Preserve process mutation and release checkpoint |
| Rollback | Discard local overlay | Discard Redis buffer; no Redis mutation occurred | Restore checkpoint, reconnect, health and digest checks |
| Conflict behavior | Shared-state versions where used | Exact existence/byte comparison | Not an optimistic key conflict model |
| Measured scale | Microseconds | GET/commit in low milliseconds | Prior Stage 15B process checkpoint/restore in tens of milliseconds |

The CRIU timing included in `comparison.json` is prior Stage 15B evidence from the privileged LinuxKit environment, not a simultaneous rerun or an identical workload. It is useful for mechanism scale only, not a direct performance ranking.

## Conflict and failure interpretation

The external conflict was a clean pre-commit negative result: the first observation no longer matched Redis, so no T1 Redis write or local state commit occurred. The external writer's `C` value was preserved.

The injected commit failure exposes the remaining cross-system gap. The coordinator commits application state before the final Redis flush. If the Redis response is unavailable at that point, local state may be committed while Redis persistence is incomplete or unknown. The implementation reports `PARTIALLY_COMMITTED`; it does not claim success, rollback, or exactly-once recovery.

In this deterministic injection the post-run oracle read `A`, but the classification remains `UNKNOWN` because a real transport timeout may occur after Redis applies a command but before the client receives its response. Read-back or durable operation-token reconciliation is not implemented.

## Provenance interpretation

The GET generated runtime-owned `RuntimeSourceType.TOOL_RESULT` provenance with the inference transaction and session identity. The same source ID was attached to the derived `InferenceState` memory entry and buffered Redis SET. Model-provided provenance was not consulted.

This records lineage; it does not make the Redis value trusted or authoritative. Authority still requires an explicit runtime-issued grant.

## Honest negative results and limitations

- Local application commit and Redis flush are not atomic.
- An ambiguous Redis response has no exactly-once recovery protocol.
- Exact-value conflict checking does not detect ABA when bytes return to their original value.
- The run covers one standalone localhost Redis instance, one database, and GET/SET/DELETE only.
- No Redis Cluster, Sentinel, replicas, failover, TLS, authentication, production pooling, or cross-slot evaluation.
- No claim applies to SQL, MCP, RAG services, or arbitrary databases.
- Redis is not copied, checkpointed, or restored as `InferenceState`.
- The CRIU comparison is historical and environment-specific.
- Timings are a small local research sample, not production capacity measurements.
