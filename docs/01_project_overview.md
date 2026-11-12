# Project overview

Transactional Inference State asks whether selected mutable inference/agent
state and requests for externally visible actions can be treated as a
transaction. Mutations are tentative until validation:

```text
Request → BEGIN → transaction-local state → execution/proposed operations
        → validation ─ ACCEPT → COMMIT
                     └ REJECT → ROLLBACK
```

The transactional scope is application/runtime state: session memory,
scratchpads, caches, retrieved data, tool results, pending writes, metadata,
security state, explicit shared state, and staged effects. It is not a process,
VM, accelerator-memory, or model-weight snapshot. Model weights remain read-only
and outside the transaction.

The runtime is model-agnostic. Deterministic and optional Ollama adapters produce
text above the trusted boundary; neither is required by the transaction core.
The model proposes operations, while trusted code parses, scopes, validates,
commits, rolls back, or discards them.

## Status categories

- **Implemented:** mechanisms represented by source and deterministic tests.
- **Observed:** values in versioned `evaluation_results/` files.
- **Interpretation:** bounded explanations of those observations.
- **Not implemented:** durability, real services, recursive taint tracking,
  thread safety, and distributed transactions.

See [architecture](04_architecture.md), [results](14_results.md), and
[claims](25_research_claims.md).

