# Stage 5 trust boundary

The trusted computing base consists of the transaction runtime, strict plan
parser, operation executor, policy validator, session/shared-state managers,
effect manager, snapshot strategies, and integrity digest implementation.

User prompts, retrieved content, model-adapter output, proposed operations,
tool results, and provenance labels are untrusted data. A model adapter returns
text only. The entire plan is parsed and schema-checked before execution. The
trusted executor can invoke only enumerated transaction-scoped operations; it
does not expose state objects or simulated services to the model.

Provenance is descriptive metadata in Stage 5, not a security decision or a
complete taint-tracking mechanism. Plans commit or roll back as a unit;
selective sub-operation commit is outside the current design.
