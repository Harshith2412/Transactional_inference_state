# Executable end-to-end transaction traces

The executable scenarios in `tests/test_end_to_end_trace.py` validate the trust boundaries documented in [the exact execution path](48_exact_execution_path.md). They use the real `SessionManager`, `TransactionManager`, snapshot strategy, parser, operation executor, effect manager, provenance registry, and simulated tool/service classes.

No Redis, SQL, MCP, or other external system is introduced.

## Trace vocabulary

The tests maintain a small observation-only `ArchitectureTrace` with stable architectural milestones:

```text
MODEL_PLAN_PARSED
TX_BEGIN
READ_TENTATIVE / WRITE_TENTATIVE
EFFECT_STAGED
VALIDATION_DECISION
TX_COMMIT / TX_ROLLBACK
```

This does not modify runtime behavior. Each test also asserts the runtime's actual `EventLog` vocabulary, including `transaction_begin`, `state_mutation`, `validation`, `commit`, `rollback`, `EFFECT_STAGED`, `EFFECT_DISCARDED`, `PROVENANCE_CREATED`, and `PROVENANCE_DISCARDED`.

## Scenario A: accepted application-state mutation

The deterministic model proposes a `MEMORY_WRITE`. `parse_model_plan` creates the typed plan, `TransactionManager.begin` creates transaction-private state, and `OperationExecutor` routes the write through `TransactionManager.write_private`. The test proves the committed session remains unchanged before validation. Acceptance followed by `commit` copies the transaction result into committed application state.

```text
MODEL_PLAN_PARSED → TX_BEGIN → WRITE_TENTATIVE
                  → VALIDATION_DECISION(accept) → TX_COMMIT
```

## Scenario B: rejected application-state mutation

A model plan replaces a nested profile value with an administrative permission. The transaction-local copy changes while the committed object remains byte-for-byte structurally equal to its pre-transaction deep copy. Rejection and rollback leave the committed state exactly unchanged.

```text
MODEL_PLAN_PARSED → TX_BEGIN → WRITE_TENTATIVE
                  → VALIDATION_DECISION(reject) → TX_ROLLBACK
```

## Scenario C: rejected staged external effect

An `EMAIL_SEND` operation is mapped through `TransactionalTools.send_email` to `EffectManager.stage`. The effect record reaches `STAGED`, but `FakeEmailService.sent_messages` stays empty. Rejection changes the effect to `DISCARDED`; the target service is never invoked.

```text
MODEL_PLAN_PARSED → TX_BEGIN → EFFECT_STAGED
                  → VALIDATION_DECISION(reject) → TX_ROLLBACK
```

The email service is a project-written deterministic simulation. The scenario demonstrates deferred externally visible action semantics, not real network delivery.

## Scenario D: simulated read as transaction-local input

The trusted driver invokes the read-only `SimulatedResearchTool.lookup_project_status`. It creates authoritative `TOOL_RESULT` provenance with `TransactionManager.issue_provenance`, then stores the result through `write_private` with that source ID. Both value and provenance metadata exist in transaction-local state but not committed state. Rollback removes the source from `ProvenanceRegistry` and leaves no committed derived value or provenance association.

```text
TX_BEGIN → READ_TENTATIVE → WRITE_TENTATIVE
         → VALIDATION_DECISION(reject) → TX_ROLLBACK
```

“Disappear” here means absent from committed state and the authoritative provenance registry. As documented previously, closed transaction strategy objects can remain internally referenced by the transaction manager; rollback is semantic isolation, not secure memory erasure.

## Invariants demonstrated

- Model output becomes executable only after strict parsing into a closed operation schema.
- Writes target transaction-private application state before commit.
- Committed application state is unchanged during speculation.
- Accepted writes become committed through the selected snapshot strategy.
- Rejected writes do not alter committed state.
- Staged effects do not execute before commit and are discarded after rejection.
- Runtime-issued tentative provenance is removed on rollback.
- Model-declared provenance is not used as an authority grant.
