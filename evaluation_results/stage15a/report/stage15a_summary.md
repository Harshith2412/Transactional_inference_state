# Stage 15A Summary

This host is macOS arm64. Native CRIU and DMTCP checkpoint/restore was not run,
and no success is claimed. Deterministic application baselines confirm that
external-process mutation persists without a checkpoint. A CI-only in-memory
oracle validates state models, canonical digests, structural comparisons, and
the flagship transcript, but is explicitly not counted as a checkpoint backend.

The negative boundary tests show that restoring service memory does not restore
a separate observer record or filesystem mutation. Stage 15B integration is not
justified from this host's measurements; the prepared Linux runners must first
produce successful native integrity, socket, failure, and performance results.
