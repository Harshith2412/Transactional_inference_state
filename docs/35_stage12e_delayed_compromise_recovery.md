# Stage 12E: delayed persistent compromise and selective recovery

## Delayed threat model

Stage 12E studies an unsafe outcome that appears transactions after its causal
state was committed. The flagship chain begins with an untrusted retrieval in T1,
persists it as memory, derives a paraphrased summary in T3, a cache entry in T5,
and later context in T7, then rejects a simulated email containing `DEMO-SECRET`
in T8. Transactions T2, T4, and T6 commit unrelated benign state.

Recovery is not retroactive rollback. Earlier commits remain historical facts.
The mechanism performs lineage-based attribution, contamination analysis,
selective quarantine, and invalidation of currently usable derived state.

## Authoritative lineage graph

`LineageGraph` is a standard-library, process-local directed acyclic graph. Nodes
represent runtime sources, transactions, committed memory, summaries, caches,
shared values, context, and effects. Edges are added only for explicit trusted
runtime dependencies. Text similarity, field names, and lexical content never
create edges.

Source nodes reuse authoritative provenance IDs where practical. Persistent state
nodes retain their source, user, session, transaction, trust label, and optional
typed `StateReference`. Lineage therefore survives paraphrasing, renaming, mock
encoding/decoding, cache copies, tool-result persistence, and cross-session flows
that were explicitly allowed or declassified. A missing parent chain is marked
unverified and treated conservatively; it is not treated as clean.

The graph exposes deterministic ancestor and descendant traversal, root users,
sessions, transactions, and sources, plus first/all untrusted ancestor queries.
Multiple roots are preserved rather than collapsed to the unsafe contributor.

## Contamination and ground truth

Given a suspicious effect, contamination analysis finds direct sources, upstream
untrusted or unverified roots, their explicitly registered descendants, committed
state on the chain, affected transactions, and unrelated active committed nodes.
Branches downstream of a contaminated root are included; unrelated roots are not.

Evaluation scenarios store expected origins and node sets outside the graph query.
The engine receives only the suspicious node ID. Precision, recall, F1,
over-quarantine, and under-recovery are computed after the engine returns.

## Recovery planning and application

Analysis, planning, and application are separate operations. A recovery plan is
bound to the graph revision, preventing a stale plan from applying after lineage
changes. The first recoverable persistent value downstream of an unsafe root is
quarantined; later recoverable descendants are invalidated. Unrelated recoverable
state receives an explicit preserve step.

Quarantined values remain available through trusted inspection with their full
node evidence but are blocked from ordinary transaction reads. Invalidated values
remain historical evidence in committed state and lineage but are marked unusable.
The runtime read gate checks typed state references. Audit events record root-cause
queries, contamination identification, plan creation, quarantine, invalidation,
and application.

An already-executed irreversible effect could not be reversed by this mechanism.
The flagship effect is rejected before execution under existing effect semantics.

## Measured controlled results

The corpus contains 25 handcrafted delayed scenarios across ten families, with
delays of 1, 3, 5, 8, and 12 transactions. Its denominators are 25 attacks, 365
contaminated nodes, and 50 unrelated nodes. All 25 unsafe outcomes were detected;
all 25 roots, origin users, sessions, transactions, and sources were recovered.
Contamination precision and recall were 100%; recovery succeeded in 25/25;
unrelated-state preservation was 100%; over-quarantine and under-recovery were 0%;
post-recovery leakage was zero. These perfect results describe a controlled corpus
with complete explicit dependencies and must not be generalized to semantic or
real-world causal attribution.

The flagship quarantined `memory-M1`, invalidated `summary-S1`, `cache-C1`, and
`context-X1`, preserved three unrelated values, and blocked normal post-recovery
reads. The original source was `source-000001`, session `SA`, user `A`, transaction
`txn-000001` in the recorded run.

## Graph growth and performance

Graph storage grew from 100 nodes/99 edges/29,827 estimated bytes to 1,000/999/
301,626 bytes and 10,000/9,999/3,046,625 bytes. At 10,000 nodes, median ancestor
and descendant queries were approximately 4.08 ms and 3.92 ms; median root-cause
query was 85.09 ms; contamination analysis was 99.85 ms; recovery planning was
13.81 ms. These are local Python measurements over linear controlled graphs.

On a small recoverable chain over 15 repetitions, median/p95 contamination analysis
was 94.4/111.8 µs, planning 9.0/11.3 µs, and application 32.2/36.8 µs.

No provenance compaction was implemented. Stage 12E does not establish an
ancestry-preserving proof for compression across branches and security boundaries;
the measured graph growth is retained as the result.

## Limitations

Dependencies remain explicit and can be incomplete. The graph, invalidation state,
quarantine, and audit log are in memory. Direct access to raw `InferenceState`
objects is inside the trusted boundary; enforcement applies to ordinary manager
reads. Shared-state recovery is represented but not durably persisted. The corpus
has controlled branching and no semantic inference, database, graph service, or
LLM. Storage grows without garbage collection. Selective recovery cannot undo
external observations or rewrite history, and no further feature stage was begun.
