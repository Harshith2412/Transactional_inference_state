# Stage 12C: cross-session information-flow enforcement

## Threat model and principle

Stage 12C asks whether a value originating under one user/session can influence a
different session through shared in-memory infrastructure. Shared storage is not
treated as public. Model-declared metadata remains untrusted; decisions consume
runtime-issued Stage 12A/B provenance. Stage 12D quarantine and selective commit
are not implemented.

## Principal, policy, and outcomes

`SecurityPrincipal` contains `user_id` and `session_id`. `FlowPolicy` evaluates
the current principal, destination scope, direct source IDs, root lineage, trust
labels, optional `FlowCapability`, and trusted declassification rules. Ground
truth labels are held only by the evaluation harness.

Default rules are:

- same user and session: allow;
- trusted system/public root: allow;
- cross-user origin: deny;
- same-user cross-session origin: deny;
- missing provenance across sessions: deny;
- exact runtime-issued declassification for the destination field: allow;
- invalid or differently scoped capability: deny when capability enforcement is enabled.

Outcomes are separate from transaction status and include allowed, public,
declassified, missing-provenance, cross-session, cross-user, and capability-scope
decisions. Events record each field decision.

## Shared-field provenance and enforcement points

`VersionedValue` retains an immutable tuple of per-field source-ID mappings.
`write_shared_object()` validates every supplied source ID before staging the
object. Shared key versions and conflict checks remain unchanged. At commit, the
object and its field map publish together.

`read_shared_fields()` evaluates only requested fields and returns a filtered
projection. A denied field is not included. Checks therefore occur when trusted
code attaches provenance to shared writes and when another principal uses a
shared field. Private writes remain protected by transaction/session ownership;
effect construction continues to retain provenance from Stage 12A. Stage 12C
does not duplicate policy calls at every internal copy operation.

The current isolation semantics are private transaction-local isolation,
committed shared reads, atomic key-level optimistic conflict checks, and explicit
flow-policy enforcement. There are no selectable database isolation levels.

## Declassification and capabilities

`DeclassificationRegistry` issues immutable runtime-owned rules containing the
source ID/session, exact destination scope, reason, issuer, and monotonic order.
It accepts only committed runtime provenance whose origin session matches the
rule. Issuance logs `DECLASSIFICATION_ISSUED`. A rule authorizes use without
rewriting source history.

`FlowCapability` binds `shared.read` authority to user, session, and destination
scope. A capability issued to A fails when presented by B. This is an optional
flow-policy check and does not redesign PolicyV1/V2 capability semantics.

## Flagship results

Session A stored `display_name`, `private_token`, and public `weather` in one
shared object. Before declassification, B received only `weather`; both A fields
were filtered. After trusted declassification of `display_name`, B received
`display_name` and `weather`, while `private_token` remained filtered. Restricted
fields leaked: 0. Provenance before and after declassification was identical.

A raw copied token with no field source IDs produced
`FLOW_DENIED_MISSING_PROVENANCE`. A laundering chain
`A input → retrieval → summary → cache → B` retained four explicit nodes; root
queries returned user A, session SA, and the originating transaction. B access
was denied. A mixed A-private/public-derived value retained both roots and was
restricted by default.

## Deterministic corpus

The corpus covers committed leakage, cache collision, retrieval/tool caches,
shared summaries, laundering, label stripping, source mixing, mixed-field JSON,
and a dirty read. Among 10 unauthorized cases decided by FlowPolicy, 10 were
blocked and none leaked. One public valid flow was allowed and no false block was
observed. These tiny handcrafted denominators do not establish a general 0% FPR
or universal protection. The dirty read was prevented by transaction isolation
and is not counted as a flow-policy success.

## Concurrent stress evaluation

The standard-library thread harness pre-creates transactions, synchronizes field
reads with barriers, rolls each read transaction back, and concurrently commits
same-key collision writes. `SharedState.read/apply` uses an in-process lock so
version check and write are atomic. Three runs were measured at each scale.

| Sessions | Runs | Private blocked | Declassified allowed | Public allowed | Leaked | Conflict aborts | Median run throughput | Median run P95 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 3 | 30 | 30 | 30 | 0 | 27 | 4,692 tx/s | 68.792 µs |
| 25 | 3 | 75 | 75 | 75 | 0 | 72 | 5,388 tx/s | 63.375 µs |
| 50 | 3 | 150 | 150 | 150 | 0 | 147 | 4,688 tx/s | 82.166 µs |
| 100 | 3 | 300 | 300 | 300 | 0 | 297 | 4,842 tx/s | 71.250 µs |

Across all runs, 555 unauthorized private-field attempts were blocked, 555
declassified and 555 public fields were allowed, and zero restricted fields were
returned. The 543 collision aborts are concurrency outcomes, not policy blocks.
Throughput is non-monotonic and local; it is not production capacity.

## Flow overhead

A 5,000-iteration Python 3.13.9 microbenchmark measured medians:

| Operation | Median |
|---|---:|
| baseline dictionary field read | 0.125 µs |
| provenance-aware field lookup | 1.542 µs |
| same-session policy check | 5.875 µs |
| cross-session denied check | 6.084 µs |
| cross-session declassified check | 5.417 µs |

These isolate in-process operations and exclude transaction, model, network, and
durability costs.

## Root queries and limitations

The registry now provides root source, user, session, and transaction queries by
traversing explicit parents. It is not the delayed-compromise graph planned for
Stage 12E.

Limitations include handcrafted attacks, only one authorized corpus field,
explicit rather than inferred lineage, exact field-scope declassification, flat
shared-object filtering, key-level shared conflicts, Python-thread scheduling,
in-memory non-durable registries, and no cryptographic attestation. The harness
does not prove race freedom for arbitrary runtime use.

The trusted mechanism grows from Stage 12B's 9 modules/1,958 LOC to 10 modules
and 2,220 LOC, with zero third-party runtime dependencies. The new trusted module
contains principals, decisions, declassification, capability binding, and flow
rules; stress/reporting code is outside the count.

Stage 12D was not started.
