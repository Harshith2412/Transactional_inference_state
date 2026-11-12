# Stage 15A.3: Scoped external participants

Stage 15A.3 defines a defensible participant boundary without integrating CRIU
with `TransactionManager`. Stage 15A.2 established 200/200 individual restores,
20/20 sequential barrier-group restores, reconnect support, and explicit
filesystem/observer exclusions. Fresh finalized-oracle validation added 20/20
tool and 20/20 RAG restores.

## Capability and eligibility contract

A participant describes process scope, reconnect behavior, filesystem and
external-effect rollback, child/group support, privilege requirements, health
and state oracles, mutation quiescing, and observable failure. Eligibility is
fail-closed. `SINGLE_PROCESS_CHECKPOINTABLE` requires one managed process,
successful CRIU checkpoint/restore, a reachable health endpoint, structural and
SHA-256 oracles, mutation quiescing, fresh reconnect, and observable restore
failure. Filesystem or unmanaged effects must not be assumed transactional.

The simple tool and RAG/cache services are `ELIGIBLE_SINGLE_PROCESS`. A
filesystem-backed tool, observer-mutating tool, persistent-socket-required tool,
parent/child tool, and atomic multi-service group are rejected. Checkpoint
metadata binds backend, participant, path, expected digest, sequence, process
identity, endpoint, and scope and has a canonical metadata hash.

## Portability and process scope

No independent Linux host or VM was available. Status is
`SECOND_ENVIRONMENT_UNAVAILABLE`: native evidence remains limited to privileged
Docker Desktop LinuxKit arm64. A non-privileged container lacked
`CAP_SYS_ADMIN` and `CAP_CHECKPOINT_RESTORE`; `criu check` refused to proceed.

The simplified process-tree reattempt again checkpointed but did not restore a
healthy parent. It is `PROCESS_TREE_NOT_SUPPORTED`. Future scope is therefore
strictly `SINGLE_PROCESS`; arbitrary managed children are outside the measured
boundary.

## Groups, sockets, and external resources

Multi-service restore remains `SUPPORTED_SEQUENTIALLY` under a mutation barrier,
with atomic snapshots not established. A design-only checkpoint set records
participant IDs, handles, timestamps, digests, barrier ID, order, and skew and
distinguishes `CONSISTENT_UNDER_BARRIER_ASSUMPTION` from inconsistent sets.

Persistent client survival is false; fresh reconnect is true. The contract is:
invalidate, restore, health-check, reconnect, and verify digest. Mutable
filesystem state and unmanaged observer effects survived restore and make a
checkpoint-only participant ineligible.

## Draft Stage 15B interface and lifecycle

The future participant interface would expose eligibility, quiesce, checkpoint,
restore, reconnect, health check, state verification, and checkpoint release.
On rejection, local rollback would be followed by client invalidation, external
restore, health, reconnect, and digest verification. A failure must become
`EXTERNAL_ROLLBACK_FAILED` or `PARTIAL_ROLLBACK_FAILURE`, never `ROLLED_BACK`.
This is documentation only.

## Recommendation

Scoped Stage 15B integration is justified for eligibility-enforced
`SINGLE_PROCESS` participants. It must reject filesystem-dependent, unmanaged-
effect, persistent-socket-required, process-tree, and atomic-group claims.
Reconnect is mandatory and privileged LinuxKit portability remains a paper
limitation. No integration was started in this stage.
