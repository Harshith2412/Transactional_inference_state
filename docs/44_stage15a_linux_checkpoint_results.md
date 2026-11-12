# Stage 15A Linux checkpoint results

This document extends the [macOS feasibility study](43_stage15a_external_checkpoint_feasibility.md)
with native Linux measurements. It does not modify or integrate with
`TransactionManager`.

## Environment

Experiments ran in an Ubuntu 24.04 arm64 privileged container on Docker Desktop's
LinuxKit 6.12.54 VM. CRIU 4.2.1 and DMTCP 4.2.0 were compiled from official
release sources because Ubuntu arm64 did not provide package candidates. CRIU
ran as effective UID 0 with all container capabilities, unconfined seccomp, and
unconfined AppArmor. DMTCP checkpointing ran through its coordinator.

`criu check` reported “Looks good.” `criu check --all` reported limitations:
veth creation and UFFD unsupported, NSID unavailable, dirty tracking off,
libnftables absent, and compatible-task C/R unavailable. These do not invalidate
the measured Python service restores but constrain generalization.

## Exact state restoration

CRIU checkpointed, mutated, killed, and restored both services. Tool state
returned from counter 1, role admin, and unsafe history to counter 0, role user,
and empty history. RAG state returned from authorization admin plus poison cache
to authorization user and empty cache. In both cases the restored SHA-256 digest
exactly equaled the pre-checkpoint digest and differed from the mutated digest.

Tool checkpoint/restore measured 32.10/21.82 ms and a 20.09 MB image. RAG
measured 27.98/17.91 ms and 20.10 MB. Restored PIDs and ports matched in this
container. New connections worked; the core trial required reconnection. A
separate pre-existing-connection checkpoint shape failed and is not counted as
state-restore failure.

DMTCP created checkpoint images for both services (about 59.1 MB), and checkpoint
commands returned successfully. Restart commands returned zero but no live
participant rejoined the coordinator and neither port became reachable.
Therefore both DMTCP restore-integrity results are failures. Command exit status
alone is explicitly insufficient evidence.

## Scaling and mutation density

CRIU completed 5/5 trials at each 1, 10, 50, and 100 MB. Median checkpoint times
were 36.48, 52.16, 45.15, and 60.67 ms; median restore times were 22.89, 36.39,
30.76, and 46.35 ms. Median images were 22.20, 41.07, 72.54, and 124.97 MB.
Mutation-density restores succeeded at 1, 100, and 10,000 keys, measuring 21.91,
22.10, and 34.27 ms respectively. These are local descriptive measurements.

Twenty independent size-matrix checkpoint/restore cycles succeeded without
state drift. A dedicated 50-cycle sequence, simultaneous multi-service restore,
compression comparison, and real checkpoint filesystem/observer trials were not
completed and remain explicit gates. Sequential individual success is not
cross-process atomicity.

## Recommendation

CRIU is `PARTIALLY_SUITABLE` and the primary candidate for further Stage 15B
work. DMTCP is `NOT_SUITABLE` in this arm64 environment. Integration is **not yet
justified**: CRIU needs a dedicated 50-cycle test, simultaneous participant test,
explicit socket-adapter behavior, and native negative-boundary/failure matrices.
Nothing here proves filesystem, remote-effect, database, or arbitrary-process
rollback, distributed transactions, or production readiness.
