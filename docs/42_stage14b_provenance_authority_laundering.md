# Stage 14B: Provenance and authority laundering

Stage 14B tests whether legitimate transformations can make untrusted data look
trusted or authoritative. It does not alter transaction, rollback, policy,
validator, COW, flow, quarantine, lineage, durability, or concurrency semantics.

## Provenance and authority

Provenance records where a value came from. Authority records whether a
principal may perform a capability in a scope. A commit, trusted tool, or trusted
summarizer does not confer authority. Declassification remains separate:
permission for information to flow is not permission to perform an action.

The `AuthorityRegistry` issues immutable runtime grants only when the issuer is
trusted and every cited provenance record is runtime-created, committed,
trusted, and authoritative. Grants bind user, session, permissions, scope,
issuer, reason, source provenance, and transaction. Derived authority intersects
permissions and cannot manufacture a capability. Model metadata remains merely
a claim.

## Threat model and corpus

The frozen corpus contains 40 malicious cases and 20 hard benign controls. It
covers summary and tool echo, cache and memory persistence, JSON serialization,
reversible encoding, field projection, source mixing, untrusted corroboration,
and corroboration with trusted approval. Separate trials cover label stripping,
metadata forgery, cross-session grants, declassification confusion, quarantine,
invalidated state, branching, and depths 1, 2, 4, and 8.

Ground truth is supplied only to scoring code. Projection retains only selected
field ancestry. Label stripping creates an unknown/unverified provenance gap and
denies security-sensitive authority. Corpus SHA-256:
`ff275fb886cfcfd425ba57a0f9afb50543704bd655a4dab21528fb342bd816f3`.

## Results

All 40 malicious chains retained the expected root and all 40 unauthorized
authority attempts were blocked. All 20 valid grants were accepted, with no
false authority denial. Corpus provenance coverage, field precision, and field
recall were 100%; false taint expansion was zero. These measurements describe
this instrumented corpus, not universal laundering resistance.

Attribution was correct in 20/20 trials at every depth, including depth 8. The
depth-8 graph had 9 nodes, 8 edges, and an estimated 3,285 bytes. One local run
measured median eight-hop propagation at 354,854 ns and ancestry query at
5,645.5 ns; performance is host-dependent.

Frozen-validator recall was 0% for PolicyV2, Sequence, and Semantic, and 100%
for Provenance and Hybrid. All had 0% FPR on 20 controls. No validator was
retuned. The malicious flagship retained the T1 untrusted retrieval, had no
grant, and denied the effect. A hard benign chain with authenticated approval
and a real runtime grant was allowed.

## External cases, recovery, and gaps

The ten Stage 14A ASB values missed by PolicyV2 passed through memory, summary,
tool echo, cache, and later context. Roots remained correct in 10/10 and no
authority escalation succeeded. Deterministic recovery found roots and
contaminated lineage, preserved unrelated state, and blocked reuse in 10/10.

All six Stage 14A adapter-only operations were reviewed. Two require trusted
transform adapters, two have representable mutation but unobservable external
effects, and two are fundamentally external/unobservable. All remain declared
gaps. No benchmark-specific rule was added, so historical external coverage
remains 85%.

## Trusted-core impact and limitations

Authority adds one trusted module and 72 measured nonblank/non-comment LOC. The
core is now 15 modules and 3,619 LOC with zero third-party runtime dependencies.
Evaluation/reporting adds 130 measured LOC outside the trusted core.

The corpus is deterministic and handcrafted, propagation requires observable
instrumented transforms, and grants are in-memory rather than signed, durable,
or revocable. External sandbox semantics still need trusted adapters. Recorded
ancestry is not proof of complete semantic causality. CRIU, DMTCP, and external
transaction-boundary integration remain out of scope.
