# Stage 15A.2: CRIU reliability and external boundaries

This standalone study extends Stage 15A Linux without integrating CRIU into
`TransactionManager`. It ran in the same privileged Ubuntu 24.04 arm64 container
on Docker Desktop LinuxKit with CRIU 4.2.1.

Tool and RAG services each completed 50/50 exact checkpoint–mutate–restore
cycles. The optional tool extension completed 100/100, giving 150/150 tool and
50/50 RAG restores. Every cycle passed command status, reachability, structural
and SHA-256 equality, port preservation, and new-client connection checks. No
state or port drift occurred. Runner FD and process counts returned to baseline.
Checkpoint directories grew because each measured image was intentionally
retained; `/proc/net/tcp` counts also increased from transient/TIME_WAIT sockets,
so the study does not claim zero socket resource drift.

Twenty paired tool/RAG cycles restored both services successfully. The services
were paused from mutation by the harness and checkpointed sequentially, not
atomically; median skew was about 61 ms. A required deliberate RAG mutation
between checkpoints restored tool state from the first logical moment and RAG
state from the second. Both CRIU commands succeeded while the consistency oracle
failed, demonstrating that sequential checkpoints are not an atomic snapshot.

With an existing persistent client, CRIU checkpoint failed in 5/5 trials. New
connections after normal restore succeeded, producing the strategy
`RECONNECT_SUPPORTED`: a future adapter must invalidate old clients, restore,
reconnect, and verify health. Transparent connection survival is not claimed.

Under real CRIU restore, service process state reverted while both a service
filesystem write and unmanaged-observer write persisted. Participant rollback
therefore is not filesystem or world rollback. A managed-child process-tree
trial checkpointed but failed restore/parent health; it is `RESTORE_FAILED` even
though the child PID was observable. Arbitrary process-tree support is not shown.

Six failure cases were classified fail-closed. In particular, command success is
never enough: reachability, health, structural equality, digest equality, and
understood port/socket behavior form the restore oracle.

Ten runs at each 1, 10, 50, and 100 MB provide min, median, p95, max, and standard
deviation for checkpoint latency, restore latency, and image size in the raw
artifacts. All 40 restores passed. A second independent Linux environment was
not available, and the observed minimum remains a privileged, unconfined
container with all capabilities.

## Draft future contract

```python
class ExternalCheckpointBackend(Protocol):
    def checkpoint(participant) -> CheckpointHandle: ...
    def restore(handle) -> RestoreResult: ...
    def release(handle) -> None: ...
    def health_check(participant) -> bool: ...
```

A participant would identify its participant ID, process identity, endpoint,
checkpoint handle, expected state digest, and socket reconnection policy. This
is documentation only.

## Gate

CRIU is `RELIABLE_WITH_SCOPED_LIMITATIONS`: individual reliability and
sequential barrier-group tests pass, failure detection is fail-closed, and the
external boundary is explicit. Stage 15B remains **not justified** because the
managed-child trial failed, all evidence is from privileged LinuxKit, and no
second Linux host validated the result. No integration was started.
