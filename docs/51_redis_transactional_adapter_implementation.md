# Redis transactional adapter implementation

## Scope

This stage implements the narrow API-mediated design from [the Redis adapter design](50_redis_transactional_adapter_design.md). It supports one Redis participant per inference transaction and exactly three logical operations:

```text
GET
SET
DELETE
```

It does not modify or reuse the CRIU participant. It does not make Redis part of `InferenceState`, expose a Redis client to the model, or claim distributed atomicity.

## Components

`redis_participant.py` contains the trusted mechanism:

- `RedisTransport`: minimal transport protocol;
- `RedisTransactionalParticipant`: owner-checked read cache, read set, and buffered write set;
- `RedisTransactionContext`: participant lifecycle and tentative data;
- `RedisTransactionCoordinator`: bridge to `TransactionManager` BEGIN/COMMIT/ROLLBACK;
- immutable read, expectation, write, and result records;
- explicit unavailable, conflict, and commit errors.

`redis_transport.py` contains `SocketRedisTransport`, a dependency-free RESP2 client restricted to localhost. Its public transport surface is PING, GET, validation, and atomic compare-and-apply. It runs one fixed project-owned Lua script; model/user-provided scripts and arbitrary commands are impossible through the interface.

The transport is held in the participant's private `_transport` field. Neither `ModelAdapter`, `ModelPlan`, nor `OperationExecutor` receives it. The current `OperationType` enum was deliberately not broadened, so model plans cannot request arbitrary Redis commands.

## Transaction behavior

BEGIN first creates the normal inference transaction, then verifies session ownership and Redis availability. Enrollment failure rolls back the local transaction.

GET checks the transaction's buffered write set first. Buffered SET returns its tentative bytes and buffered DELETE returns missing. Otherwise, the first Redis value is cached as the transaction's repeatable observation; later reads return that observation. The read set records exact bytes, existence, and a SHA-256 audit digest.

SET and DELETE validate ownership, key prefix, sizes, provenance IDs, and operation budget. A blind write first observes its committed basis. The operation is stored only in `RedisTransactionContext.write_set`; Redis is not mutated.

ROLLBACK calls the ordinary local rollback, then clears Redis read values, provenance references, expectations, and buffered writes. Because no Redis mutation occurred, no compensating Redis operation is needed.

## Commit and conflicts

Commit has two conflict checks:

```text
participant.validate(observed values)
→ local TransactionManager.commit
→ atomic Redis compare-and-apply
```

The precheck allows an already-stale transaction to abort with local status `ROLLED_BACK` before Redis or committed `InferenceState` changes. The final fixed Lua operation compares all observed keys and applies every SET/DELETE only if every exact byte value and existence bit still match. Within one Redis database/script execution, a conflict applies none of the buffered writes.

A race or outage after local commit but before/during Redis application cannot be made atomic without a cross-system protocol. It produces `TransactionStatus.PARTIALLY_COMMITTED` and a `RedisConflictError` or `RedisCommitError`; it is never reported as successful commit or rollback. The participant retains its conflict/failure context for inspection.

To keep this seam narrow, the coordinator rejects Redis transactions that also contain shared-state writes or staged executable `PendingEffect`s. CRIU enrollment and multiple Redis participants are outside this coordinator's supported composition.

## Provenance and lineage

A real Redis GET causes `TransactionManager.issue_provenance` to issue a tentative `RuntimeSourceType.TOOL_RESULT` record with the current transaction/session identity and `TrustLabel.UNKNOWN`. The model's declared provenance is never used.

`RedisRead.provenance_ids` can be attached to application state through `write_private`/`write_path`, or to a derived buffered Redis SET. The runtime verifies that every supplied ID is authoritative and belongs to the transaction. Rollback removes tentative registry records and committed application state remains free of the derived value and metadata.

A read served from the transaction's write set retains the buffered write's input provenance rather than minting a false independent Redis-read source. The prototype records provenance parent IDs but does not automatically construct every higher-level `LineageGraph` node; application lineage remains explicit as elsewhere in the repository.

## Isolation and events

Each transaction has an independent context. Transaction A's SET/DELETE exists only in A's write set, so transaction B reads committed Redis state. A reads its own buffered writes.

Events include:

- `REDIS_PARTICIPANT_ENROLLED`
- `REDIS_READ`
- `REDIS_WRITE_TENTATIVE`
- `REDIS_DELETE_TENTATIVE`
- `REDIS_PREPARED`
- `REDIS_FLUSHED`
- `REDIS_BUFFER_DISCARDED`
- `REDIS_CONFLICT`
- `REDIS_UNAVAILABLE`

Events contain participant identity and digests, not Redis values.

## Validation evidence

Portable tests use a deterministic, lock-protected `InMemoryRedisTransport` defined only in the test module. They cover buffered writes, DELETE, read-your-writes, cross-transaction isolation, provenance, forged provenance, conflicts, outages, partial commit, ownership, limits, lifecycle, prohibited resource composition, and frozen policy fingerprints.

The guarded integration test uses `SocketRedisTransport` against a disposable localhost Redis database. It verifies real commit, rollback, read-your-writes, and cleanup without adding `redis-py`.

## Dependencies and trusted surface

No project dependency was added. The real transport uses Python standard-library `socket`; Redis itself remains an optional external test/runtime service.

Trusted-code growth for this stage is:

```text
redis_participant.py:  285 non-comment LOC
redis_transport.py:     72 non-comment LOC
runtime.py hook:         6 non-comment LOC
total trusted growth:  363 non-comment LOC across two new modules plus one hook
```

## Limitations

- No atomicity between local Python state and Redis.
- No durable recovery or exactly-once reconciliation after ambiguous timeout.
- Exact-value conflict detection cannot detect ABA when a value changes and returns to identical bytes before validation.
- Only one standalone Redis endpoint/database is evaluated; no Cluster, Sentinel, replica, failover, or cross-slot semantics.
- Localhost-only RESP transport, no TLS/authentication or production connection pooling.
- GET/SET/DELETE only; no expiry options, conditional SET variants, data structures, pub/sub, streams, modules, or administrative commands.
- Byte values only. Serialization and schema policy belong to trusted application code.
- Redis data is not authoritative merely because it was transactionally read.
- Closed runtime transaction records remain process-memory objects; rollback is semantic isolation, not secure erasure.
