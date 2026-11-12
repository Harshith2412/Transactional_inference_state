# System architecture for review

This document describes the repository as implemented. It separates three different meanings of “transactional state.” They share transaction IDs and trusted coordination, but they do not use the same rollback mechanism and do not form a distributed transaction.

## System overview

Legend:

```text
[PROJECT / TRUSTED]       code written in this repository and treated as trusted
[PROJECT / UNTRUSTED]     data produced by project test adapters but treated as untrusted
[OFF-THE-SHELF]           software not implemented by this project
[EXTERNAL PARTICIPANT]    state outside the orchestrator-managed InferenceState
```

```text
 UNTRUSTED MODEL                                      [UNTRUSTED]
        |
 COMMODITY INFERENCE ENGINE                          [OFF-THE-SHELF / UNTRUSTED]
        |  raw text; optional implementation uses Ollama
        v
 STRUCTURED MODEL PLAN                               [PROJECT DATA / UNTRUSTED]
        |  ModelPlan produced by strict parse_model_plan()
        |  allowed operations today: memory/cache read/write, email request
        v
 TRUSTED ORCHESTRATOR                                [PROJECT / TRUSTED]
        |  currently composed from experiment/agent drivers,
        |  PolicyV1/PolicyV2, OperationExecutor, TransactionManager
        |
        +-----------------------+------------------------+
        |                       |                        |
        v                       v                        v
  1. ORCHESTRATOR-       2. API-MEDIATED         3. CHECKPOINT-MEDIATED
     MANAGED STATE          EXTERNAL PARTICIPANT     EXTERNAL PARTICIPANT
  [PROJECT / TRUSTED]    [PROJECT / TRUSTED]      [PROJECT / TRUSTED]
        |                       |                        |
  InferenceState         RedisTransactional-      ExternalParticipant-
  FineGrainedCOW         Participant              Coordinator
        |                       |                        |
  private speculative    GET external value       eligibility check
  writes                 buffer SET/DELETE        + CRIU checkpoint
        |                read own writes                 |
        |                       |                  normal service API
        |                optimistic exact-value   mutation after checkpoint
        |                conflict validation             |
        |                       |                        |
   +----+-----+           +-----+------+           +-----+------+
   |          |           |            |           |            |
 COMMIT    DISCARD      COMMIT       ROLLBACK    COMMIT       ROLLBACK
 apply COW no copy-back  flush write  drop local  keep new     restore process,
 to session; committed  set through  buffer;     process      reconnect, health,
 state changes state    Redis API    Redis stays state        structural+digest check
                           |                        |
                           v                        v
                   Redis server              eligible tool/RAG service
                   [OFF-THE-SHELF /           [PROJECT SERVICE /
                    EXTERNAL PARTICIPANT]       EXTERNAL PARTICIPANT]
                                              CRIU is [OFF-THE-SHELF]
```

The arrows are coordination paths, not one atomic commit protocol. A transaction can be locally committed and still fail while flushing Redis. A local rollback can succeed and still be followed by a failed CRIU restore. Those outcomes are explicitly reported as partial or external failures.

## Entry boundary: model to trusted execution

`ModelAdapter.generate` returns text. The optional `OllamaModelAdapter` talks to the off-the-shelf Ollama engine over localhost HTTP. Ollama, model weights, retrieved text, and generated text are outside the trusted runtime.

`parse_model_plan` is project-written trusted code. It parses the complete JSON document before any operation executes. It accepts only the closed `OperationType` set and rejects unknown commands or extra fields.

`OperationExecutor` maps accepted plan operations onto owner-checked transaction methods. It never hands a `TransactionManager`, Redis transport, Redis socket, CRIU handle, or arbitrary Python callable to the model.

There is not yet one production orchestrator class. `EvaluationHarness`, `IndependentPolicyHarness`, and `RealisticResearchAgent` are project-written drivers that compose parsing, policy, provenance, transaction execution, and resolution in slightly different orders.

## Path 1: orchestrator-managed state

`SessionManager.create_session` allocates one `InferenceState` per session. `InferenceState` contains application-selected Python dictionaries and lists: session memory, scratchpad, application cache, retrieved data, tool results, pending memory writes, metadata, security state, lineage metadata, and provenance associations.

It is not raw process memory. It does not include model weights, inference-engine KV caches, interpreter stacks, sockets, file descriptors, or arbitrary service state.

`TransactionManager.begin` selects a private-state strategy. `FineGrainedCOWStrategy` keeps a reference to committed state and copies only the mutable branch addressed by a `FieldPath`. The full-copy and delta strategies are also implemented.

Before commit, `write_private` and `write_path` modify only transaction-private state. Commit applies the copied branches to the session's committed `InferenceState`. Rollback does not copy them back, so committed state remains unchanged.

Example: a model plan proposes `MEMORY_WRITE(theme="dark")`. `OperationExecutor` calls `TransactionManager.write_private`. Other code holding the committed session object still sees the old value until `TransactionManager.commit`.

## Path 2: API-mediated Redis participant

`RedisTransactionalParticipant` owns a private `RedisTransport`. The model never receives that transport. The dependency-free `SocketRedisTransport` implements a small localhost RESP2 client; a deterministic in-memory transport exists only in tests.

GET contacts Redis only for the transaction's first observation of a key. The participant records the exact bytes and existence state in a transaction-local read set. It also asks `TransactionManager.issue_provenance` for a runtime-owned `TOOL_RESULT` source record.

SET and DELETE do not contact Redis. They are copied into the transaction's private Redis write set. A later GET checks this write set first, so the transaction reads its own buffered value. Another transaction has a different context and continues to read committed Redis state.

Commit first validates that Redis still matches the read set. After local application commit, a fixed project-owned Lua script atomically compares all observed Redis values and applies all buffered writes within one Redis server. Rollback clears the local Redis buffer and does not need to undo Redis because no tentative write was sent.

This path has an honest split-commit gap. If local state commits and Redis then becomes unavailable or changes during the final window, the runtime reports `PARTIALLY_COMMITTED`; it does not report successful commit or rollback.

Redis is not copied into `InferenceState`. Only an explicitly read value may be stored as transaction-local application input, with its runtime provenance ID.

## Path 3: CRIU checkpoint-mediated participant

`ExternalParticipantCoordinator` accepts at most one participant whose eligibility is exactly `ELIGIBLE_SINGLE_PROCESS`. Unsupported filesystem-dependent, unmanaged-effect, persistent-socket, process-tree, and atomic multi-service configurations are rejected.

Before normal transaction execution, the coordinator quiesces the service and asks `CRIUCheckpointParticipant` to invoke the off-the-shelf CRIU executable. CRIU writes process checkpoint images. The service then resumes and can be mutated through its normal localhost API.

Commit preserves the service's current mutated process state and releases the checkpoint. Rollback first rolls back local `InferenceState`, then invalidates the old client, restores the process, reconnects, checks health, and requires structural and SHA-256 equality with the checkpoint-time service state.

If restore fails, the transaction becomes `EXTERNAL_ROLLBACK_FAILED`, not `ROLLED_BACK`. This is coordinated recovery of one process, not rollback of its filesystem, remote effects, or arbitrary service dependencies.

## Trace 1: Redis read-modify-write commits

The implemented executable example is `redis_evaluation.evaluate_scenarios`. It is a trusted evaluation driver; the current `ModelPlan` enum does **not** contain `REDIS_GET`, `REDIS_SET`, or `REDIS_DELETE`.

Therefore the repository does not yet implement a direct “model emits Redis operation” route. If a model emitted an unknown Redis command in the current plan schema, `parse_model_plan` would reject it. The implemented trace begins when trusted application code has selected the Redis operation:

```text
Trusted evaluation driver                         [PROJECT / TRUSTED]
  |
  | RedisTransactionCoordinator.begin("S", participant)
  v
TransactionManager.begin                          local InferenceState speculative
  |
  | RedisTransactionalParticipant.get("counter")
  v
SocketRedisTransport.get ───────────────────────▶ Redis GET counter
                                                   returns b"10"
  |
  | TransactionManager.issue_provenance(TOOL_RESULT)
  | trusted derivation: int(10) + 1
  | write_private("derived_counter", b"11", provenance_ids=...)
  | RedisTransactionalParticipant.set("counter", b"11", provenance_ids=...)
  v
Redis write set contains SET counter=11           Redis still exposes 10
  |
  | PolicyValidator accepts; TransactionManager.validate
  | RedisTransactionalParticipant.prepare checks observed 10
  | TransactionManager.commit applies local state
  | RedisTransactionalParticipant.flush
  v
fixed atomic compare-and-apply script ───────────▶ Redis becomes 11
```

The measured run proved that Redis remained `10` before commit and became `11` afterward. The derived local memory value and buffered Redis write carried the runtime-issued source ID.

This trace should be read as the implemented external-state mechanism plus its current orchestration seam—not as an already implemented model-plan Redis command.

## Trace 2: CRIU-backed RAG mutation aborts

The implemented executable example is `stage15b_linux_runner.rejected("rag", ...)`. It also uses trusted evaluation code rather than a model-directed RAG operation. The current plan executor is not wired to the CRIU coordinator.

```text
Trusted native evaluation driver                  [PROJECT / TRUSTED]
  |
  | starts project RAG/cache HTTP service          [EXTERNAL PARTICIPANT]
  | creates CRIUCheckpointParticipant
  | ExternalParticipantCoordinator.begin
  v
eligibility == ELIGIBLE_SINGLE_PROCESS
  |
quiesce → CRIU dump                               [OFF-THE-SHELF CRIU]
  |           checkpoint authorization="user", cache={}
resume
  |
  | trusted driver calls normal service API
  v
service mutates authorization="admin"
service mutates cache["poison"]="approved disclosure"
local TransactionManager.write_private adds tentative contamination
  |
  | PolicyValidator rejects; TransactionManager.validate
  | ExternalParticipantCoordinator.rollback
  v
local rollback
  → invalidate client
  → CRIU restore checkpoint
  → fresh reconnect
  → health check
  → structural equality
  → SHA-256 equality
  v
local state restored
RAG authorization="user"
RAG cache={}
transaction status ROLLED_BACK
```

The native LinuxKit experiment observed exact structural and digest restoration. It did not prove that a commodity model can currently invoke this RAG service through `ModelPlan`; that integration is absent.

## What is project-written and what is off-the-shelf

Project-written trusted mechanisms include:

- strict `ModelPlan` parsing and `OperationExecutor`;
- `TransactionManager`, `InferenceState`, full copy, delta, and fine-grained COW;
- Redis participant, coordinator, restricted RESP transport, and fixed compare-and-apply script;
- CRIU participant interface, coordinator, verification logic, and checkpoint metadata handling;
- policy, provenance, lineage, flow, authority, event, and effect-staging code.

Project-written external/test services include `FakeEmailService`, `SimulatedResearchTool`, and the Stage 15 localhost tool/RAG HTTP process.

Off-the-shelf components are Python and its standard library, optional Ollama and its model runtime, Redis server, CRIU, the Linux kernel checkpoint facilities, Docker Desktop/LinuxKit, and pytest.

## Claims the implementation supports

- Application-managed Python state can remain private until commit and be discarded on rejection.
- Selected Redis writes can remain buffered, support read-your-writes, remain invisible to other transactions, and abort on an observed-value conflict.
- One validated single-process service can be checkpointed with CRIU and restored after rejection in the measured LinuxKit environment.

## Claims the implementation does not support

- A unified model-plan path to Redis or the CRIU-backed RAG service.
- Distributed transactions or atomic commit across Python state and Redis.
- Generic transaction support for SQL, MCP, arbitrary RAG services, or remote effects.
- Copying Redis or process memory into `InferenceState`.
- Filesystem rollback, process-tree rollback, atomic multi-service rollback, or persistent connection transparency.
- Secure erasure of every closed transaction object from Python memory.
