# Stage 15A: External checkpoint feasibility

Stage 15A is a standalone measurement study. It does not integrate a checkpoint
backend with `TransactionManager` and does not modify transaction, policy,
validator, provenance, authority, COW, lineage, durability, or flow semantics.

## Environment and availability

The measured host is macOS/Darwin on arm64. CRIU and DMTCP are absent, and both
are classified `HOST_UNSUPPORTED_FOR_NATIVE_CHECKPOINT`. No native checkpoint,
restore, socket, PID, image-size, or latency success is claimed. The repository
contains `tools/stage15a_linux_probe.sh` for an explicitly configured Linux host;
it detects versions and runs `criu check` but never installs privileged software.

On Linux, CRIU must pass `criu check`, have permission to inspect and restore the
target process tree, and be tested with the host's namespaces, seccomp policy,
LSM, open descriptors, and TCP configuration. DMTCP requires
`dmtcp_checkpoint`, its coordinator, and compatible launch/restart behavior.
Those backend tests must run in a disposable VM or appropriately configured
container. Package installation and privilege changes remain operator actions.

## Services and state model

Two standalone standard-library service fixtures are provided. The localhost
HTTP entrypoint is `python -m transactional_inference_state.stage15a_service`.
The tool service stores a counter, key/value map, and history. The RAG/cache
service stores documents, retrieval cache, query history, summary cache, and an
authorization value. It uses no vector database or external service.

State is serialized as canonical sorted compact JSON and hashed with SHA-256.
Restore integrity requires both structural equality and exact digest equality.
The required mutations change tool role `user` to `admin`, increment the
counter, append `unsafe-operation`, change RAG authorization to `admin`, and
write the poison cache entry.

## Lifecycle and measurements

The intended native lifecycle is: start the service, record state and digest,
checkpoint, mutate, verify a changed digest, restore, reconnect if necessary,
and require structural and digest equality. A failed checkpoint or restore must
stop the experiment and may never be reported as successful rollback.

The Linux run should separately measure tool and RAG services, then both
services. Sequential checkpoints are not atomic coordinated checkpointing.
Record PID behavior, existing-connection usability, reconnect requirement, port
preservation, checkpoint/restore median and p95, image bytes, state sizes 1, 10,
50, and 100 MB, mutation densities 1, 100, and 10,000 keys, and 10/50/100 cycles.

## Current results

The no-checkpoint baseline shows that both external service mutations persist.
A deterministic in-memory oracle proves only the state-model, digest, transcript,
and comparison logic; it is labeled `IN_MEMORY_TEST_ORACLE` and is not counted
as CRIU or DMTCP evidence.

The negative filesystem experiment restores the service state model but leaves
the file value `mutated`. A separate observer record also remains. Thus even a
successful process restore would not establish arbitrary-world rollback: remote
APIs, email, financial actions, independent services, and filesystem contents
outside a captured storage mechanism remain external effects.

Failure cases—command failure, incomplete image, restore failure, kill during
checkpoint, and kill before restore—are all fail-closed and recorded as
`STOP_AND_REPORT_FAILURE`.

## CRIU versus DMTCP

Both backends are currently `UNAVAILABLE`; selecting a winner would be
unsupported. A Linux run must compare state integrity, latency, image size,
privileges, descriptors, sockets, process-tree capture, shared memory, identity
behavior, and failure modes. CRIU commonly operates through kernel checkpoint
facilities and image directories; DMTCP uses coordinated user-space launch and
restart. These architectural descriptions are not measurements.

## Boundary levels and recommendation

- Level 0: `InferenceState` only.
- Level 1: `InferenceState` plus tool-process checkpoint.
- Level 2: Level 1 plus RAG/cache-process checkpoint.
- Level 3: future external or durable services.

Stage 15A evaluates preparation for Levels 1 and 2 only. Stage 15B integration
is not justified by this macOS run. It should proceed only after a Linux host
demonstrates repeatable native restore integrity, acceptable overhead, understood
socket reconnection, safe failure behavior, and orphan-free repeated cycles.

## Limitations

There are no native backend measurements on this host. The HTTP fixtures are
small deterministic models, not production services. Filesystem rollback and
remote-side-effect rollback are expressly absent. Cross-process atomicity is not
demonstrated, and performance matrix entries remain `NOT_RUN_BACKEND_UNAVAILABLE`.
