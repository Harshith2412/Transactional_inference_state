# Exact execution path and current trust boundaries

This document describes the repository as implemented. It is not a proposed redesign. In particular, the project does not currently have one top-level production orchestrator that owns every step; experiment and agent drivers compose several trusted components.

## Current boundary map

```text
 UNTRUSTED / COMMODITY                         TRUSTED PROJECT CODE
 ┌───────────────────────────┐       ┌──────────────────────────────────────┐
 │ user prompt               │       │ experiment / agent driver            │
 │ retrieved text            │       │  ModelPlanRunner or explicit calls   │
 │ Ollama model process      │──────▶│  parse_model_plan                    │
 │ raw model-output string   │       │  PolicyV1 / PolicyV2                 │
 └───────────────────────────┘       │  OperationExecutor                   │
                                     │  TransactionManager                  │
                                     └──────────────┬───────────────────────┘
                                                    │
                                      references / copies / overlays
                                                    │
                                     ┌──────────────▼───────────────────────┐
                                     │ ORCHESTRATOR-MANAGED STATE           │
                                     │ InferenceState per SessionManager    │
                                     │ snapshot / delta / fine-grained COW  │
                                     │ provenance, lineage, pending effects │
                                     └──────────────┬───────────────────────┘
                                                    │ commit or scoped CRIU
                                     ┌──────────────▼───────────────────────┐
                                     │ EXTERNAL PARTICIPANTS / SERVICES     │
                                     │ FakeEmailService (simulation)        │
                                     │ Stage 15 tool/RAG HTTP process       │
                                     │ CRIU checkpoint/restore              │
                                     │ Redis/SQL/MCP: conceptual only       │
                                     └──────────────────────────────────────┘
```

The model is never given a `TransactionManager`, session object, effect manager, capability registry, or direct mutable `InferenceState` reference by the model adapter interface. It returns text. Trusted code decides whether that text becomes a typed operation and which scoped API implements it.

## Exact module and class ownership

| Responsibility | Actual module and symbol | Current role |
|---|---|---|
| Model/inference boundary | `model.py`: `ModelAdapter`, `DeterministicModelAdapter`, `OllamaModelAdapter.generate` | Returns an untrusted string. The Ollama adapter uses a localhost HTTP API and the standard-library `urllib`; the deterministic adapter returns configured text verbatim. |
| Model transport normalization | `stage11.py`: `ModelTransportNormalizer` | Normalizes live-model transport output in later evaluation paths; it is not called by the basic `ModelPlanRunner`. |
| Typed plan schema | `operations.py`: `ModelPlan`, `ProposedOperation`, `OperationType`, `Provenance` | Immutable application operation representation. The plan's `source` is a model claim, not authoritative runtime provenance. |
| Trusted parsing | `operations.py`: `parse_model_plan`, `_parse_operation` | Parses the entire JSON document, rejects extra/missing fields, unknown operations, bad argument types, duplicate IDs, invalid provenance labels, and non-JSON arguments before execution. |
| Plan execution | `operations.py`: `OperationExecutor.execute`, `_execute_one` | Maps the closed operation enum to owner-checked transaction APIs or effect staging. It does not execute arbitrary function names supplied by the model. |
| Minimal runner | `operations.py`: `ModelPlanRunner.prepare` | Calls adapter, parser, and executor and rolls back on parse/execution errors. It assumes the caller has already begun a transaction. It does not run policy validation or commit/rollback after successful preparation. |
| Realistic orchestration driver | `stage13a.py`: `RealisticResearchAgent.run` | Explicitly composes retrieval, begin, provenance, parsing, `PolicyV2.evaluate`, COW writes, operation execution, `PolicyValidator`, and commit/rollback. This is experimental application code, not a general orchestrator API. |
| Structured session state | `runtime.py`: `InferenceState` | Application-level dictionaries/lists for memory, scratchpad, cache, retrieved data, tool results, pending writes, metadata, security state, lineage metadata, and provenance metadata. |
| State allocation | `runtime.py`: `SessionManager.create_session` | Constructs a new independent `InferenceState`; `get_session` returns the committed object reference owned by that session. Initial application data is populated by callers after creation. |
| Transactions | `runtime.py`: `TransactionManager.begin`, `validate`, `commit`, `rollback` | Owns transaction IDs, lifecycle, session ownership, private strategy context, shared read/write sets, provenance closure, event logging, and effect-manager callbacks. |
| Full snapshots | `runtime.py`: `SnapshotManager`, `FullCopyStrategy` | Uses `deepcopy`. Stage 1 legacy mode also stores a pre-transaction snapshot; normal full-copy mode deep-copies committed state into transaction-local state. |
| Delta overlay | `runtime.py`: `DeltaContext`, `DeltaStrategy` | Keeps a reference to committed `base`, plus copied key-level writes/deletes. Full state is deep-copied only if materialization is required. |
| Fine-grained COW | `cow.py`: `FieldPath`, `COWContext`, `FineGrainedCOWStrategy` | Keeps a reference to committed `base`; copies the mutable branch needed for an explicit nested path. Arbitrary callback materialization deep-copies the full state. |
| Shared application state | `runtime.py`: `SharedState`, `VersionedValue` | Separate versioned in-memory application state with optimistic read/write conflict checks; it is not `InferenceState` and is not an external Redis/SQL store. |
| Pending effects | `effects.py`: `PendingEffect`, `EffectManager.stage`, `TransactionalTools.send_email` | Deep-copies effect arguments into an in-memory transaction-owned staging table. Rejection marks staged effects discarded; commit invokes `execute_transaction`. |
| Simulated target | `effects.py`: `FakeEmailService.send_email` | Project-written in-memory simulation. No network message is sent. Executed effects are appended to `sent_messages`. |
| Provenance | `provenance.py`: `ProvenanceRegistry`; `runtime.py`: `issue_provenance`, provenance-aware reads/writes | Runtime-issued tentative records live in a transaction-indexed registry, then move to committed records or are discarded. IDs stored in `InferenceState.provenance_metadata` associate state paths with records. |
| Automatic propagation | `propagation.py`: `TrackedValue`, `ProvenanceEngine` | Project-specific tracked-value helpers for derived provenance; not automatically applied to all arbitrary Python computation. |
| Lineage | `lineage.py`: `LineageGraph`, `LineageNode`, `LineageEdge` | Explicit project-managed DAG and state references. Edges are recorded by application code; content-derived edges are not inferred automatically. |
| Cross-session flow | `flow.py`: `FlowPolicy`, `DeclassificationRegistry` | Checks authoritative root provenance, principal/session identity, destination, capabilities, and explicit declassification. |
| Operation capabilities | `policy.py`: `CapabilityGrant`, `CapabilitySet`, `PolicyContext` | Inputs to operation policy evaluation. `stage8.standard_capabilities` supplies common experimental grants. |
| Authority | `authority.py`: `AuthorityRegistry`, `AuthorityGrant`, `AuthorityContext` | Runtime-issued action authority backed by committed trusted provenance. It is deliberately separate from claimed plan provenance and flow labels. |
| Plan policy | `policy.py`: `PolicyEngine.evaluate`, `PolicyV1`, `PolicyV2` | Evaluates typed operations against trusted context and returns a `PolicyDecision`; it does not itself mutate transaction lifecycle state. |
| Lifecycle validator | `runtime.py`: `PolicyValidator`, `TransactionManager.validate` | Converts a deterministic boolean or state callable into `VALIDATED` or `REJECTED`. Agent drivers commonly set it from a prior `PolicyV2` decision. |
| Alternative validators | `stage13c.py`: validator classes and `validator_set` | Experimental independent validators used in evaluation; they are not implicitly invoked by every `TransactionManager`. |
| External participant coordinator | `stage15b.py`: `ExternalTransactionParticipant`, `ExternalParticipantCoordinator` | Adds eligibility, checkpoint-before-BEGIN, commit cleanup, local-first external rollback, explicit external failure, retry, events, and journal metadata for at most one eligible process. |
| CRIU adapter | `criu_participant.py`: `CRIUCheckpointParticipant` | Invokes the off-the-shelf `criu` executable, manages image directories and process identity, requires fresh reconnect, and checks health, structural state, and digest equality. |
| Durable metadata journal | `durability.py`: `TransactionJournal`, `DurableTransactionRuntime` | Optional append-only JSONL records with hash chaining and optional `fsync`. This is a separate experimental authoring/recovery path, not transparent persistence of the live `TransactionManager`, `InferenceState`, or CRIU image bytes. |

## Concrete rejected mixed-operation trace

The exact existing scenario is `evaluation.provenance_spoofing_scenario`, executed through `EvaluationHarness.run(..., EvaluationMode.TRANSACTIONAL)`. Its plan proposes both `MEMORY_WRITE(role="admin")` and `EMAIL_SEND(...)`. The “external tool” target here is the project-written `FakeEmailService`, not Redis, SQL, or MCP.

1. `provenance_spoofing_scenario()` returns an `EvaluationScenario` containing the user prompt, retrieved attack text, raw configured model output, initial memory, and `policy_accept=False`.
2. `EvaluationHarness.run` selects `DeterministicModelAdapter(scenario.model_output)` and calls `EvaluationHarness._run_once`.
3. `_run_once` calls `SessionManager.create_session("session")`, creating the committed `InferenceState`. It populates `session_memory` with a deep copy of `initial_memory`, then takes an evaluator-only `deepcopy(state)` and `state_digest(state)`. It constructs `FakeEmailService`, `EffectManager`, and `TransactionManager(..., validator=PolicyValidator(False), effect_manager=effects)`.
4. `DeterministicModelAdapter.generate(scenario.prompt, retrieved_content=...)` returns the configured raw JSON string. With `OllamaModelAdapter.generate`, this same boundary would send the combined prompt to external Ollama and return its response text. Neither adapter receives a runtime-state reference.
5. `parse_model_plan(raw)` invokes `json.loads`, checks the complete schema, and calls `_parse_operation` for both operations. It returns an immutable `ModelPlan`; nothing has executed yet.
6. `TransactionManager.begin("session")` resolves the committed object with `SessionManager.get_session`. The default `FullCopyStrategy.begin` deep-copies the complete `InferenceState` into a new `Transaction.strategy_context`, and the transaction becomes `ACTIVE`.
7. `OperationExecutor.execute(plan, tx, "session")` iterates through `_execute_one`:
   - `MEMORY_WRITE` calls `TransactionManager.write_private(..., "session_memory", "role", "admin")`; `FullCopyStrategy.write` deep-copies the value into transaction-local state. The committed role remains `"user"`.
   - `EMAIL_SEND` calls `TransactionalTools.send_email`, then `EffectManager.stage`. `stage` checks ACTIVE status and ownership, validates runtime provenance IDs (none are supplied in this Stage 6 harness), deep-copies arguments into `PendingEffect`, stores it in `_effects`, and changes it to `STAGED`. `FakeEmailService.send_email` is not called.
8. `_run_once` calls `TransactionManager.validate(tx)`. `PolicyValidator.fixed_result()` returns false, changing `ACTIVE` to `REJECTED`. This evaluation scenario does not invoke `PolicyV1`/`PolicyV2`; its expected policy result is configured data.
9. `_run_once` calls `TransactionManager.rollback(tx)`. `EffectManager.discard_transaction` changes the email to `DISCARDED`; `ProvenanceRegistry.discard_transaction` removes tentative runtime provenance; and the transaction becomes `ROLLED_BACK`. Normal session mode does not copy a snapshot back because committed state was never changed.
10. `_run_once` verifies that the original committed `InferenceState` reference still equals its pre-transaction copy and digest and that `FakeEmailService.sent_messages` is empty. The closed `Transaction` remains in `_transactions` and references its strategy context; rollback closes logical access but is not secure physical erasure.

```text
provenance_spoofing_scenario → EvaluationHarness.run → _run_once
  ├─ SessionManager.create_session + initial-memory deepcopy
  ├─ DeterministicModelAdapter.generate                    [untrusted text]
  ├─ parse_model_plan → _parse_operation                   [typed ModelPlan]
  ├─ TransactionManager.begin
  │    └─ FullCopyStrategy.begin → deepcopy                [local state copy]
  ├─ OperationExecutor.execute → _execute_one
  │    ├─ TransactionManager.write_private                 [tentative memory]
  │    └─ TransactionalTools.send_email
  │         └─ EffectManager.stage → deepcopy              [pending, not sent]
  ├─ TransactionManager.validate → PolicyValidator(False)  [REJECTED]
  └─ TransactionManager.rollback
       ├─ EffectManager.discard_transaction                [STAGED → DISCARDED]
       ├─ ProvenanceRegistry.discard_transaction
       └─ committed InferenceState remains unchanged
```

`model_experiments.run_mixed_operation_experiment` demonstrates the same memory/effect rejection semantics through direct calls, but it begins the transaction before calling the deterministic adapter. This is one example of the repository's non-uniform orchestration order.

### Policy-rich agent variant

`RealisticResearchAgent.run` uses the richer path. It retrieves documents with `DeterministicRetriever.retrieve`, begins a COW transaction, issues runtime provenance with `TransactionManager.issue_provenance`, calls `parse_model_plan`, constructs `PolicyContext`, calls `PolicyV2.evaluate`, writes retrieval/tool data through `TransactionManager.write_path`, executes plan operations with `OperationExecutor.execute`, assigns `PolicyValidator(decision.allowed)`, then calls `TransactionManager.validate` and `commit` or `rollback`. It explicitly records lineage afterward. Model generation is external to `run` for deterministic scenarios because `AgentScenario.raw_plan` is already populated; `run_live_agent_subset` obtains the raw plan from `OllamaModelAdapter` before invoking this path.

## Copy, reference, staging, and persistence semantics

| Data | Current handling |
|---|---|
| Session lookup | `SessionManager.get_session` returns the committed `InferenceState` object reference. Ownership is enforced by transaction/session IDs, not by an OS memory boundary. |
| Full-copy transaction | Complete state is deep-copied at BEGIN. Reads and writes also return/store deep copies. COMMIT deep-copies all dataclass fields back while preserving the committed top-level object identity. |
| Delta transaction | `DeltaContext.base` references committed state; replacement values are deep-copied into an overlay. Reads are copied. Materialization deep-copies the full base. COMMIT copies overlay values into committed containers. |
| Fine-grained COW transaction | `COWContext.base` references committed state. The container chain beneath a modified top-level key is copied; explicit path values are deep-copied. Arbitrary materialization deep-copies all state. |
| Shared state | Values are deep-copied on read/write and persisted only in the process-local `SharedState._entries` after conflict-checked commit. |
| Pending effects | Arguments are deep-copied into `EffectManager._effects`. They persist only in memory unless separately represented in the optional journal. Rejection changes status to `DISCARDED` and clears provenance IDs, but retains the effect record and its arguments for observation; commit may cause the simulated target mutation. |
| Provenance | Registry records are immutable dataclasses. Tentative records are held separately by transaction ID; commit publishes them in the committed registry and rollback removes them. State stores source IDs, not duplicate records. |
| Lineage | Nodes are deep-copied into and out of `LineageGraph`; edges and state references are explicit metadata. The graph is process-local unless separately journaled/exported. |
| Event log | `EventLog.record` deep-copies detail data into an append-only in-memory list. |
| Durable journal | Serializes metadata records to a local JSONL file and can call `fsync`; it does not serialize the whole Python heap or make session state database-durable. |
| CRIU participant | CRIU serializes eligible external process state into checkpoint image files. Those images concern the external process, not the Python `InferenceState` dataclass. Journal records contain only checkpoint metadata. |

## `InferenceState` is not process memory

`InferenceState` is a Python dataclass defining named, application-level containers. Snapshot strategies traverse/copy its Python object graph using `copy`/`deepcopy`; they do not inspect virtual-memory mappings, stacks, file descriptors, interpreter internals, model weights, KV caches, threads, sockets, or arbitrary heap objects outside fields reachable from the dataclass.

Raw process checkpointing exists only in the separate Stage 15 path: `CRIUCheckpointParticipant` invokes CRIU for one eligible external service process. The orchestrator's own `InferenceState` remains managed through application-level snapshot strategies. Therefore “transactional inference state” in the core means structured state selected by the application, not transparent rollback of the inference engine or Python process memory.

## Project code versus off-the-shelf components

Written in this repository:

- all transaction, snapshot, delta, COW, shared-state, effect-staging, policy, provenance, lineage, flow, authority, journal, experiment, reporting, and participant-coordination Python modules;
- `DeterministicModelAdapter`, `OllamaModelAdapter` integration code, strict plan parser, and operation executor;
- `FakeEmailService`, deterministic retriever/tool, and Stage 15 localhost tool/RAG service;
- the CRIU adapter and Docker/evaluation harness (but not CRIU itself).

Off-the-shelf or external:

- Python and its standard library (`json`, `dataclasses`, `copy`, `urllib`, `subprocess`, threading, hashing, filesystem APIs);
- Ollama and its model weights/runtime when optional live-model experiments are enabled;
- CRIU and the Linux kernel checkpoint facilities used by opt-in Stage 15 tests;
- Docker Desktop/LinuxKit used for the measured CRIU environment;
- pytest as the test runner.

There is currently no production Redis, SQL database, generic RAG service, or MCP/tool-server integration. `application_cache` and `SharedState` are in-process Python structures. Stage 15's HTTP tool/RAG service is a project-written experimental process. References to Redis, SQL, and MCP describe possible external-service categories, not current adapters.

## Architectural ambiguities and seams

1. **No single orchestration entry point.** `ModelPlanRunner` covers generation/parsing/execution but not BEGIN, policy validation, or successful closure. `RealisticResearchAgent` and experiment functions each assemble the lifecycle themselves.
2. **Two meanings of validation.** `PolicyEngine.evaluate` returns a rich plan decision, while `TransactionManager.validate` consults the simpler configured `PolicyValidator`. Drivers bridge them manually by assigning `PolicyValidator(decision.allowed)`.
3. **Two provenance representations.** `operations.Provenance` is untrusted declared plan metadata; `provenance.RuntimeProvenanceRecord` is authoritative runtime-issued provenance. Correct callers must supply `runtime_provenance` to `OperationExecutor`; the simple model experiments generally do not.
4. **Lineage is explicit but not uniformly integrated.** The runtime can enforce lineage reads, but application drivers record many lineage nodes/edges themselves, sometimes after transaction resolution.
5. **“External effect” and “external participant” differ.** `EffectManager` defers requested actions and cannot undo executed irreversible effects. `ExternalParticipantCoordinator` restores one eligible process with CRIU. Neither implies rollback of remote Redis/SQL/MCP consequences.
6. **Persistence terminology is contextual.** “Committed” normally means visible in the current process's committed application state. Only optional journal records and CRIU image files survive process termination; ordinary `InferenceState`, provenance, authority, event, and lineage objects are not database-persistent.
7. **Trust is logical, not an OS sandbox.** Classes enforce ownership and strict schemas in one Python address space. Except for the external model/service processes, components are not isolated by a separate security process boundary.
8. **Rollback is semantic restoration, not secure erasure.** Closed transaction records and discarded effect records remain in manager-owned dictionaries. They cannot be used through normal open-transaction APIs, but the repository does not zero memory or promptly delete every tentative Python object.
