# Minimal Redis transactional adapter design

Status: design only. This document proposes a research prototype; it does not add Redis, a Redis client dependency, or runtime behavior.

## Architectural placement

Redis would be an **API-mediated external state participant**. It is neither part of `InferenceState` nor restored by CRIU.

```text
                         trusted Python process
  untrusted model     ┌───────────────────────────────────────────┐
 ┌───────────────┐    │ parser / policy / orchestrator            │
 │ prompt + text │───▶│                                           │
 │ no clients    │    │ TransactionManager                        │
 └───────────────┘    │   └─ InferenceState snapshot/COW          │ A
                      │                                           │
                      │ RedisTransactionCoordinator               │
                      │   └─ RedisTransactionContext              │
                      │       read_set + buffered write_set       │
                      │   └─ RedisTransport (trusted capability)  │
                      └──────────────────────┬────────────────────┘
                                             │ Redis protocol/API
                                      ┌──────▼──────┐
                                      │ Redis data │ B
                                      └─────────────┘

  separate Stage 15 path: ExternalParticipantCoordinator
                          └─ CRIUCheckpointParticipant
                             └─ checkpoint/restore whole eligible process  C
```

The three state classes are deliberately different:

| State | Owner and representation | Tentative mechanism | Rollback meaning |
|---|---|---|---|
| A. `InferenceState` | Orchestrator-managed Python dictionaries/lists | Full copy, delta, or fine-grained COW | Discard transaction-local overlay; committed object remains unchanged |
| B. Redis | External logical keys accessed through an API | Adapter-owned read set and buffered `SET`/`DEL` write set | Discard buffered operations; Redis was never mutated |
| C. CRIU participant | Memory and execution state of one eligible external process | OS/process checkpoint image | Kill/restore process, reconnect, health-check, and verify digest |

The design does not copy all Redis contents into `InferenceState`. Only explicitly read values may be copied into transaction-local application state, with provenance, when trusted orchestration chooses to do so.

## 1. Trust boundary

The raw Redis client or socket is a trusted capability owned by the adapter. It is never passed to:

- `ModelAdapter` or model-generated code;
- `ModelPlan` or `ProposedOperation.arguments`;
- prompt templates or retrieved content;
- arbitrary tool implementations.

The model may propose a closed operation such as a future `REDIS_GET`, `REDIS_SET`, or `REDIS_DEL`, but `parse_model_plan` and a trusted executor must validate the operation, key namespace, value type/size, session ownership, and capabilities before calling the adapter. Prefer an executor-specific method over exposing a general command string. Commands such as `EVAL`, `SCRIPT`, `CONFIG`, `FLUSH*`, pub/sub, transactions supplied by the model, and arbitrary module commands must be unreachable.

The prototype should scope every participant to:

- one inference transaction ID and owner session ID;
- one configured Redis endpoint/database;
- one key prefix or explicit allowlist;
- `GET`, `SET`, and `DEL` only;
- bounded key/value sizes and operation count;
- at most one Redis participant per inference transaction.

## 2. Minimal API

Keep the transaction mechanism independent from a particular Redis package:

```python
class RedisTransport(Protocol):
    def get(self, key: bytes) -> bytes | None: ...

    def compare_and_apply(
        self,
        expected: Mapping[bytes, ExpectedValue],
        writes: Mapping[bytes, BufferedRedisWrite],
    ) -> RedisApplyResult: ...
```

`compare_and_apply` is one atomic Redis-side operation. A future production transport may implement it with `WATCH`/`MULTI`/`EXEC` or a constrained Lua script. A project-written `InMemoryRedisTransport` should provide deterministic tests without adding a dependency or starting Redis.

Proposed trusted facade:

```python
class RedisTransactionalParticipant:
    def begin(self, transaction_id: str, session_id: str) -> None: ...
    def get(self, transaction_id: str, session_id: str, key: str) -> RedisRead: ...
    def set(self, transaction_id: str, session_id: str,
            key: str, value: bytes) -> None: ...
    def delete(self, transaction_id: str, session_id: str, key: str) -> None: ...
    def prepare(self, transaction_id: str, session_id: str) -> RedisPrepareResult: ...
    def flush(self, transaction_id: str, session_id: str) -> RedisApplyResult: ...
    def rollback(self, transaction_id: str, session_id: str) -> None: ...
```

Supporting immutable records:

```python
RedisRead(key, value, exists, observed_digest, provenance_id)
BufferedRedisWrite(operation, value=None)       # SET or DEL
ExpectedValue(exists, digest, managed_version=None)
RedisTransactionContext(transaction_id, session_id,
                        status, read_set, write_set)
```

`RedisTransactionCoordinator` should bind one participant context to one `TransactionManager` transaction and enforce lifecycle ordering. It should resemble `ExternalParticipantCoordinator` structurally but must not implement the CRIU protocol: Redis has no checkpoint handle, quiesce, reconnect-after-restore, or process-state oracle.

## 3. State machine

Participant-local states:

```text
                         ┌─────────────┐
BEGIN ──────────────────▶│ ACTIVE      │
                         └──────┬──────┘
                 reads / buffered SET, DEL
                                │
                  validation accepts│validation rejects
                                │            │
                         ┌──────▼──────┐     ▼
                         │ PREPARED    │  DISCARDED
                         └──────┬──────┘
                    atomic compare-and-apply
                     ┌──────────┴──────────┐
                     ▼                     ▼
                  FLUSHED              CONFLICTED / FAILED
```

`DISCARDED`, `FLUSHED`, `CONFLICTED`, and `FAILED` are terminal for ordinary calls. Duplicate commit/rollback, use after closure, wrong-session access, and a second Redis participant must fail closed.

The enclosing inference transaction remains governed by `TransactionManager`. If Redis application fails after local commit, the enclosing transaction must use an explicit partial/external-commit failure status; it must not report an ordinary clean rollback or claim atomicity.

## 4. Read path

For `get(tx, session, key)`:

1. Verify the context is ACTIVE, belongs to `session`, and the key is in scope.
2. If the key exists in the context's write set:
   - buffered `SET` returns its buffered value;
   - buffered `DEL` returns a typed missing result.
   This is read-your-writes and performs no Redis request.
3. Otherwise call `RedisTransport.get`.
4. Record existence and a SHA-256 digest of the exact returned bytes in `read_set`. Preserve the first observation for conflict detection; repeated reads should return the first transaction snapshot value rather than silently changing the transaction's basis.
5. Ask `TransactionManager.issue_provenance` to issue tentative authoritative provenance for the external read. For the first prototype use existing `RuntimeSourceType.TOOL_RESULT`; do not trust a model-declared `operations.Provenance` label.
6. Return a copied/immutable `RedisRead`, not the client. The trusted orchestrator may store its decoded value with `TransactionManager.write_private(..., provenance_ids=(read.provenance_id,))`.
7. Record `REDIS_READ` with transaction/session/participant identity, scoped key identifier, existence, digest, and observed version if present. Avoid logging secret value bytes.

The read value is transaction-local input only if the orchestrator writes it into the transaction strategy context. Redis itself remains external, and the entire Redis keyspace is never snapshotted into `InferenceState`.

## 5. Write path

For `set` and `delete`:

1. Verify ACTIVE lifecycle, ownership, namespace, capability, size, and operation budget.
2. If the key has not been observed, read it once and record the expected existence/digest. A blind write therefore still has a conflict basis.
3. Put a copied `BufferedRedisWrite` in the context write set. A later operation for the same key replaces the earlier tentative operation deterministically.
4. Do not call Redis with `SET` or `DEL`.
5. `get` consults this write set first, providing read-your-writes.
6. Record `REDIS_WRITE_TENTATIVE` or `REDIS_DELETE_TENTATIVE`, excluding secret value contents.

Because write sets are held per transaction, transaction B reads committed Redis state and cannot observe transaction A's buffer.

## 6. Commit path

The desired logical sequence is:

```text
policy accepts
→ participant.prepare checks the original read basis
→ commit orchestrator-managed InferenceState
→ participant.flush performs atomic compare-and-apply
→ mark external participant FLUSHED
→ complete
```

`prepare` is a useful early conflict check but cannot reserve Redis state unless a Redis connection remains under `WATCH`. `flush` must therefore repeat conflict validation atomically with applying every buffered `SET`/`DEL`.

This ordering favors the current runtime's local-first convention and prevents Redis changes when ordinary policy rejects. It is **not atomic across Python state and Redis**. A crash, network error, or Redis conflict between local commit and external flush can leave local state committed while Redis is unchanged. The coordinator must surface an explicit state such as `REDIS_COMMIT_FAILED` or the existing `PARTIALLY_COMMITTED`, retain the write set and evidence, and never describe the outcome as full commit success.

For the smallest first experiment, transactions enrolling Redis should be prohibited from also using:

- `SharedState` writes that may conflict during local commit;
- irreversible `PendingEffect` execution;
- a CRIU participant;
- another Redis participant.

This restriction does not create atomicity, but makes the failure boundary observable and interpretable. Crash recovery and exactly-once external commit should be a later stage, not silently implied.

## 7. Rollback path

```text
policy rejects or execution aborts
→ TransactionManager.rollback
→ RedisTransactionalParticipant.rollback
→ clear read/write sets and tentative read cache
→ mark participant DISCARDED
```

No Redis command is needed because Redis was never mutated. Tentative Redis-read provenance is discarded by the existing `TransactionManager.rollback` path. The participant should retain only bounded audit metadata if required; secret read values and buffered values should be dropped from its active context.

Rollback of the Redis buffer is therefore different from CRIU restoration: it prevents a write rather than reversing an already visible external mutation.

## 8. Conflict-detection options

### Option A: value digest compare-and-apply — recommended minimum

At first read/write, record `(exists, SHA-256(raw bytes))`. At commit, atomically compare every current Redis value with the observation and apply the write set only if all match.

Advantages:

- detects ordinary managed and unmanaged changes;
- requires no schema change to user keys;
- deterministic and easy to test;
- supports multiple keys atomically within one Redis instance.

Limitations:

- an ABA change (value changes and later returns to identical bytes) is invisible;
- hashing large values costs time;
- equality is byte-level, not semantic.

### Option B: `WATCH`/`MULTI`/`EXEC`

On a dedicated trusted connection, `WATCH` every observed key, re-read and compare with the original observations, queue buffered writes in `MULTI`, and call `EXEC`. A null/aborted `EXEC` is a conflict.

Advantages: native Redis optimistic concurrency and atomic writes within one Redis deployment.

Limitations: connection pinning and timeout management; watch state is lost on reconnect; it still needs original-value comparison to detect a change that happened before `WATCH` began; it does not solve cross-system atomicity.

### Option C: adapter-managed version sidecars

Maintain a version key for each data key and atomically advance both on every adapter-managed write.

Advantages: detects ABA among cooperating writers and mirrors `SharedState` versions.

Limitations: unmanaged Redis writers can bypass versions; doubles metadata/key management; requires namespace governance and cleanup.

Recommended prototype: Option A implemented atomically by a constrained server-side script or a carefully bounded `WATCH` transaction. Add sidecar versions only if all experimental writers can be required to cooperate. Any mismatch aborts the Redis flush; never use last-write-wins.

## 9. Failure cases

| Failure | Required behavior |
|---|---|
| Redis unavailable during read | Fail the operation; rollback the inference transaction. No fabricated value. |
| Decode/type error | Fail closed before storing application state; retain only safe error metadata. |
| Key outside namespace or oversized value | Reject before contacting Redis where possible. |
| Redis changes after observation | Atomic compare fails; do not apply any buffered Redis writes. |
| Policy rejection | Discard buffer; no Redis mutation. |
| Failure before local commit | Roll back local transaction and discard Redis buffer. |
| Failure after local commit but before/during Redis flush | Explicit `REDIS_COMMIT_FAILED`/`PARTIALLY_COMMITTED`; do not report clean commit or rollback. Do not blindly retry without an idempotency/recovery record. |
| Ambiguous transport timeout | Treat Redis outcome as unknown until read-back/operation-token reconciliation; do not assume failure or success. |
| Process crash while buffer is only in memory | Redis remains unchanged, but the tentative operation is lost. This is safe abort behavior, not durable transaction recovery. |
| Duplicate commit call | Lifecycle error; never apply twice. |
| Wrong session/transaction | Ownership error before read or mutation. |

An optional operation token stored in the same atomic Redis apply can later make commit reconciliation safer. It is not required for the first non-durable prototype.

## 10. Provenance interaction

- Every network `GET` result receives a tentative runtime-issued source ID through `TransactionManager.issue_provenance`.
- Use `RuntimeSourceType.TOOL_RESULT` initially to avoid broadening the provenance schema. Participant ID, scoped key hash, observed digest, and read event remain audit metadata rather than model claims.
- A transaction-local `InferenceState` write derived from the result must carry that source ID through `write_private`, `write_path`, or automatic tracked-value propagation.
- Read-your-writes should preserve or derive provenance from the buffered write's trusted input source IDs; it must not mint an apparently independent trusted Redis observation.
- On rollback, `ProvenanceRegistry.discard_transaction` removes tentative read/derived records and committed state contains no associated IDs.
- On commit, the normal registry commit publishes only the provenance closure used by committed application state.
- Redis being reachable or transactional does not make its values authoritative. `AuthorityRegistry` grants remain separately required.

## 11. `PendingEffect` interaction

Redis `SET`/`DEL` should not initially be modeled as ordinary `PendingEffect` records:

- Redis supports reads during the transaction, while `EffectManager` is designed around deferred actions.
- Read-your-writes requires a participant-local overlay.
- Conflict detection must occur before/atomically with flush.
- `EffectManager.execute_transaction` runs after local commit and represents prefix failure as `PARTIAL_EFFECT_FAILURE`; it has no read set or compare-and-apply contract.

The Redis participant can reuse concepts such as transaction/session ownership, deep-copied arguments, idempotency metadata, event naming, and explicit failure states. For the first prototype, reject a transaction that tries to combine Redis enrollment with executable irreversible `PendingEffect`s. Later research may define coordinated ordering, but must expose partial outcomes rather than claim atomicity.

## 12. Comparison with CRIU participant

| Property | Redis API adapter | CRIU participant |
|---|---|---|
| Protected unit | Selected Redis keys | Whole eligible process memory/execution state |
| Read during transaction | API `GET` with read-set observation | Normal service API after checkpoint |
| Tentative writes | Buffered in trusted adapter | Service process mutates immediately after checkpoint |
| Other-client visibility before commit | No buffered value visibility | Mutated service state may be visible unless separately isolated/quiesced |
| Commit | Atomic compare-and-apply to Redis | Preserve current process state; delete checkpoint |
| Rollback | Discard buffer; no Redis call | Kill/restore process and reconnect |
| Conflict model | External key changes detected optimistically | Restore overwrites participant process state to checkpoint |
| Connection semantics | Normal Redis API connection; reconnect on transport failure | Existing client invalidated; fresh reconnect required after restore |
| Filesystem/process state | Not included | Eligible process memory only; filesystem still excluded |
| Main failure seam | Split local commit / Redis flush | Split local rollback / external restore |

Neither mechanism creates a distributed transaction. Redis compare-and-apply is atomic only within the selected Redis deployment/script execution; CRIU restore is scoped to one validated process.

## 13. Explicit non-goals

- Copying or snapshotting the Redis keyspace into `InferenceState`.
- Giving the model a raw client, connection URL, credentials, or command channel.
- Arbitrary Redis commands, Lua supplied by users/models, modules, pub/sub, streams, blocking operations, or administrative commands.
- Redis Cluster, Sentinel failover semantics, replicas, cross-slot atomicity, or multi-Redis transactions.
- More than one Redis participant per inference transaction.
- Atomicity between Redis and local Python state, SQL, MCP, CRIU, or `PendingEffect`s.
- Rollback of writes made outside the adapter.
- Durable recovery, exactly-once commit, or automatic retry after ambiguous failure.
- Treating Redis values as trusted authority.
- Changing `InferenceState`, snapshot/COW semantics, policy fingerprints, or the CRIU contract.

## 14. Proposed tests

Portable tests using `InMemoryRedisTransport`:

1. GET produces a transaction-owned `RedisRead` and runtime provenance.
2. GET result stored through `write_private` is tentative and disappears with provenance on rejection.
3. SET and DEL do not change transport state before commit.
4. Read after buffered SET returns the buffered value.
5. Read after buffered DEL returns missing.
6. A second transaction sees committed transport state, not another transaction's buffer.
7. Accepted commit flushes all writes exactly once.
8. Rejected rollback discards all writes and performs no transport mutation.
9. Changed value/existence causes a conflict and applies no writes.
10. Multi-key conflict applies none of the buffered writes.
11. Wrong-session access, use after closure, commit twice, and rollback twice fail.
12. A second Redis participant is rejected.
13. Namespace, operation-count, key-size, and value-size limits fail closed.
14. Model plan/executor tests prove no arbitrary Redis command or client object can cross the schema.
15. Redis plus executable irreversible `PendingEffect` is rejected for prototype scope.
16. Local-commit/external-flush failure receives explicit partial status.
17. Event ordering covers enrollment, read, tentative write, validation, compare, flush/discard, and conflict/failure.

Optional integration tests, only after choosing a client dependency:

- run against a disposable local Redis server;
- dirty-read prevention across two real connections;
- read-your-writes without pre-commit visibility;
- `WATCH`/Lua conflict injection;
- multi-key all-or-none apply within one Redis instance;
- disconnect and ambiguous-timeout classification;
- no credentials or values in event/journal output.

## 15. Minimal files and classes to add

No files are added by this design other than this document. A later implementation should remain small:

```text
src/transactional_inference_state/redis_participant.py
    RedisTransport                  Protocol
    RedisTransactionalParticipant  scoped read/write overlay
    RedisTransactionContext        read/write sets and lifecycle
    RedisTransactionCoordinator    TransactionManager lifecycle bridge
    RedisRead / ExpectedValue / BufferedRedisWrite / result records
    RedisConflictError / RedisCommitError

tests/test_redis_participant.py
    InMemoryRedisTransport          deterministic test transport
    portable lifecycle/isolation/conflict/provenance tests

tests/test_redis_integration.py     optional, skipped without explicit configuration
```

Only when real integration tests are authorized:

```text
src/transactional_inference_state/redis_transport.py
    RedisPyTransport               thin optional adapter over redis-py
```

Keeping the fake transport in tests avoids making simulation part of the trusted production surface. Keeping the client-specific transport separate prevents Redis package details from leaking into `TransactionManager` or `InferenceState`.

## Recommended first implementation boundary

The smallest defensible experiment is:

```text
one TransactionManager transaction
+ one RedisTransactionalParticipant
+ GET / buffered SET / buffered DEL
+ runtime provenance for GET
+ read-your-writes
+ atomic value-digest compare-and-apply
+ explicit conflict and partial-commit statuses
```

Everything else should remain out of scope until this boundary has deterministic portable tests and opt-in validation against one local Redis instance.
