# Stage 12A: provenance-aware transactions

## Scope

Stage 12A makes runtime-issued provenance transactional without implementing
dynamic taint analysis, information-flow enforcement, declassification,
fine-grained copy-on-write, quarantine, or recovery. PolicyV1 and PolicyV2 are
unchanged. The Stage 12 research freeze remains a historical baseline; Stage 12A
is a subsequent development result.

## Design

`RuntimeSourceType` now covers user input/prompt, retrieved content, tool results,
memory, model output, system context, and derived values. `TrustLabel` records
`TRUSTED`, `UNTRUSTED`, `MIXED`, or `UNKNOWN`. Immutable `ProvenanceLabel` objects
carry user, session, transaction, source, source type, and trust label.

The registry separates committed records from records tentative to a transaction.
`issue_provenance()` derives the authoritative user and session from the runtime's
session registry; callers do not supply those identities. Derived records list
one or more explicit parent source IDs. Dependency is registered by trusted code
and is not inferred semantically.

Private values use `InferenceState.provenance_metadata`, a side-table keyed by
field and entry key. This avoids wrapping every Python primitive. Shared
`VersionedValue` entries and `PendingEffect` objects store source-ID tuples.
FullCopy and Delta naturally transact the private side-table alongside the value.
Shared provenance is applied with the same version-checked write. Effects retain
source IDs on commit and clear tentative references when discarded.

At commit, tentative registry records become committed and
`PROVENANCE_COMMITTED` is logged. Rollback and optimistic conflict abort discard
all records issued by that transaction and log `PROVENANCE_DISCARDED`. Thus a
rolled-back value and its tentative lineage disappear together.

The model plan's `source` field remains a claim. Trusted `OperationExecutor` code
may separately map operation IDs to runtime source IDs. Only registry-issued IDs
are accepted; unknown IDs and tentative IDs owned by another transaction fail.
The optional `ProvenancePolicyHook` receives authoritative records through a
separate interface. Existing policies do not consume or change behavior based on
this hook.

## Deterministic evaluation

`run_provenance_experiments()` answered the four requested questions:

| Question | Result |
|---|---|
| Can committed origin be identified? | Yes in the deterministic private/shared fixture. |
| Does provenance survive commit and transaction boundaries? | Yes; Session B observed Session A/user A as the origin of a committed shared value. |
| Does rollback remove tentative state and lineage? | Yes; both the value and registry node were absent. |
| Can claimed provenance override runtime provenance? | No; a plan claiming `user_prompt` committed with authoritative `RETRIEVED_CONTENT`/`UNTRUSTED` metadata. |

Provenance was also attached to a staged effect and committed or discarded with
that effect. Events observed included `PROVENANCE_CREATED`,
`PROVENANCE_DERIVED`, `PROVENANCE_READ`, `PROVENANCE_COMMITTED`, and
`PROVENANCE_DISCARDED`, with transaction and session IDs.

The complete suite produced `276 passed, 1 skipped, 0 failed`; 13 tests are new
for Stage 12A. No previous test was removed or changed.

## Local overhead and complexity

A 2,000-iteration Python 3.13.9 microbenchmark compared one ordinary private
write with provenance issuance plus the same private write. Median measured time
was 6,291 ns without provenance and 18,209 ns with provenance, an incremental
11,918 ns (0.011918 ms). This isolates a small operation path, not full transaction
latency, and is hardware/interpreter dependent.

The Stage 10/11 complexity result remains frozen at seven modules and 1,210 LOC.
The Stage 12A trusted mechanism measurement is eight modules and 1,646 nonblank,
non-comment Python LOC with zero third-party runtime dependencies. The eighth
module contains the deterministic Stage 12A experiment and benchmark.

## Limitations

- Metadata is entry-level, not nested field-level taint.
- Derivations are explicitly registered; semantic dependencies are not inferred.
- Provenance IDs are deterministic in-process identifiers, not cryptographic attestations.
- The registry is in-memory, single-process, non-durable, and not thread-safe.
- Existing unlabelled values remain supported and return empty provenance.
- The optional policy hook exposes data but imposes no default flow rule.
- Provenance does not retroactively trace arbitrary Python computations.
- No garbage collection or chain compression is implemented.
- The microbenchmark does not measure large lineage graphs or concurrent load.

Stage 12B was not started.
