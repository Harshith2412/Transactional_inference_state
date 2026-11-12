# Stage 15B: scoped external transaction integration

## Scope and eligibility

Stage 15B enrolls at most one externally managed process. Enrollment is fail-closed and occurs only when the participant returns `ELIGIBLE_SINGLE_PROCESS`. Filesystem-dependent participants, unmanaged effects, persistent-socket requirements, process trees, and atomic multi-service groups are rejected before the local transaction becomes active.

This boundary is a coordinated rollback protocol, not a distributed transaction. It does not provide filesystem, remote-effect, process-tree, or multi-service atomicity.

## Participant lifecycle

The trusted `ExternalTransactionParticipant` contract supplies eligibility, quiesce/resume, checkpoint/restore, client invalidation/reconnect, health and exact-state verification, and checkpoint release. The CRIU adapter records participant identity, backend, endpoint, scope, sequence, process identity, state digest, checkpoint path, and a canonical metadata hash. Image contents are not trusted merely because this metadata exists.

BEGIN executes eligibility, quiesce, checkpoint, metadata recording, and resume before creating the normal ACTIVE transaction. A checkpoint error therefore leaves no ACTIVE transaction. Existing transactions that do not enroll a participant use the unchanged `TransactionManager` path.

## Commit and rollback

Commit first commits application-managed state, preserves the participant's current state, and then releases its checkpoint. Checkpoint cleanup failure is reported as `CHECKPOINT_CLEANUP_FAILED`; it does not reverse an already committed transaction.

Rollback uses deterministic local-first ordering: application state and tentative provenance are discarded before external recovery starts. This minimizes the time rejected inference state remains locally visible. It is not atomic: if external restoration fails, the local half has already completed. The transaction then becomes `EXTERNAL_ROLLBACK_FAILED`, with `local_rollback=SUCCESS` and `external_rollback=FAILURE`, and retains the original checkpoint for diagnosis or explicit retry.

External recovery invalidates the old client, quiesces, restores the original CRIU handle, establishes a fresh connection, checks reachability and health, and requires both structural equality and SHA-256 equality. Only after all checks pass is the transaction `ROLLED_BACK`. Persistent-client survival is false; connection-transparent rollback is not claimed.

## Journal and crash recovery

The journal records metadata-only `EXTERNAL_CHECKPOINT`, `EXTERNAL_RESTORE_ATTEMPT`, `EXTERNAL_RESTORE_SUCCESS`, `EXTERNAL_RESTORE_FAILURE`, and `EXTERNAL_CHECKPOINT_RELEASE` records. CRIU image bytes are never journaled.

A crash after restore begins but before success is classified `EXTERNAL_ROLLBACK_INCOMPLETE`. A success record without `TX_COMPLETE` is `EXTERNAL_RESTORE_VERIFICATION_REQUIRED`: recovery first reconnects and checks health, structure, and the expected digest. If they match, it records completion without an unnecessary duplicate restore; otherwise it explicitly retries the original handle.

## Security semantics

Checkpointability does not confer authority and restoration is not provenance sanitization. Outputs retain their existing provenance and require runtime-issued authority grants. Tentative derived provenance from a rejected transaction is discarded through the unchanged local rollback path.

| Boundary | Local state after rejection | External cache after rejection |
|---|---|---|
| Application only | restored | contaminated |
| Application + eligible participant | restored | restored and digest-verified |

## Performance and portability

The native artifact reports begin/checkpoint, commit/release, rollback/restore, health, reconnect, and verification costs alongside local-only costs. CRIU latency is reported directly. Native evidence is limited to privileged Docker Desktop LinuxKit arm64; a second independent Linux environment remains unavailable. The core adds no third-party dependency; the optional adapter requires the CRIU executable and privileged Linux facilities.
