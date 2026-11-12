# Stage 13D Limitations

- This is local crash recovery, not distributed atomicity.
- A crash after an irreversible service action but before its durable receipt is
  intrinsically ambiguous without target-side idempotency lookup.
- SHA-256 chaining detects observed-history corruption but is not authenticated.
- The prototype does not coordinate multiple process writers.
- Payloads must be canonical-JSON compatible.
- Per-record fsync inherits local filesystem and hardware durability semantics.
- Checkpointing is deferred; startup verification and replay are linear.
- Recovery projects state from the journal; integration with real services,
  databases, networks, or LLMs is outside Stage 13D.
