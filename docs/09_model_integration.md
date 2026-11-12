# Model integration and strict plans

`ModelAdapter` is a protocol whose only capability is `generate(...) -> str`.
`DeterministicModelAdapter` returns configured text for reproducible tests.
`OllamaModelAdapter` optionally calls a configurable localhost Ollama endpoint
with the standard library; absence, timeout, or invalid service response raises
`OllamaUnavailableError`. The transaction core has no Ollama dependency.

The model is outside the trusted computing base. It receives prompt/retrieval
text, not state-manager or effect-service objects. Its `ModelPlan` contains an
ordered tuple of `ProposedOperation` plus a final response. Supported operations
are `MEMORY_READ`, `MEMORY_WRITE`, `CACHE_READ`, `CACHE_WRITE`, and
`EMAIL_SEND`.

Each operation requires a nonempty unique ID, exact operation type, exact
argument object, and claimed provenance. The trusted `OperationExecutor` maps
reads/writes to transaction/session-scoped APIs and email to
`TransactionalTools`. `ModelPlanRunner` rolls back automatically when parsing or
execution fails.

## Fail-closed parser

`parse_model_plan` requires one JSON object with exactly `operations` and
`final_response`. Each operation must have exactly `operation_id`,
`operation_type`, `arguments`, and `source`. It rejects malformed JSON, missing
or additional fields, unknown operations, wrong argument types, non-JSON values,
duplicate IDs, unsupported provenance, session-reference extras, and mixed
valid/invalid plans. The complete plan is parsed before any operation executes.

Parser rejection means untrusted text never crossed the structured boundary. It
is not evidence that a compromised, executable plan was contained by rollback.

