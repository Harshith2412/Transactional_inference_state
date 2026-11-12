# Stage 13A realistic agent workload

Stage 13A evaluates the frozen runtime and PolicyV2 around a small integrated
research-assistant workflow. It is a **realistic agent workload**, not a
production deployment or evidence of real-world security.

## Architecture

The application sits above the trusted runtime:

```text
user request → lexical retrieval → context → strict plan
             → transactional memory/cache/tool/effect operations
             → frozen PolicyV2 → commit or rollback
```

Separate workload probes compose the existing Stage 12C flow policy, Stage 12D
selective resolver and quarantine, and Stage 12E explicit lineage/recovery. No
automatic provenance or lineage inference was added.

## Retrieval and corpus

The deterministic corpus has 30 local documents: 20 public technical notes,
five Session-A private notes, two Session-B private notes, and three Session-A
untrusted attack documents. Each document declares a document ID, owner,
visibility, runtime source type, and trust label. Retrieval uses token overlap
with stable document-ID tie breaking and filters session-private documents
before ranking.

## Memory, caches, tools, and effects

- User preferences, conversation facts, summaries, and notes use
  `InferenceState.session_memory`.
- Retrieval, summary, and tool-result caches use transaction-local
  `application_cache` writes.
- `lookup_project_status` is deterministic, produces runtime-issued
  `TOOL_RESULT` provenance, and performs no external I/O.
- Email is the existing simulated deferred effect. It executes only after
  commit and proves no property about real external atomicity.
- Rejected writes and retrieval-cache updates disappear together. Quarantined
  values remain outside ordinary inference state.

## Threat workflows

Twenty deterministic malicious workflows cover direct prompt injection,
semantic memory poisoning, cache poisoning, retrieval poisoning, cross-session
misuse, provenance spoofing, delayed compromise, and sequence abuse. Twenty
benign workflows exercise retrieval, preferences, summaries, cache writes,
tools, and simulated report-email completion.

## Deterministic measurements

| Metric | Result |
|---|---:|
| Benign completion | 20/20 |
| PolicyV2 detection | 9/20 |
| Persistent compromise | 11/20 |
| External-effect leakage | 0/20 |
| Containment after rejection | 9/9 |
| Cross-session leakage | 0 |
| Memory-poison persistence | 8/17 memory-writing attacks |
| Cache-poison persistence | 3/3 cache-writing attacks |

The frozen policy detected direct injection, cross-session misuse, provenance
spoofing, and sequence abuse in this corpus. It accepted semantic memory,
cache/retrieval, and delayed-state poisoning forms. Those 11 persistent misses
are recorded in `failures/failure_analysis.json`; PolicyV2 was not retuned.
The cache-poisoning probe opened a distinct later transaction, reused the
committed poisoned summary, and recorded the later inference context as affected.

The selective mixed workflow committed its safe preference and summary,
quarantined the unsafe authorization field, and suppressed the dependent
effect. The delayed workflow recovered origin user, session, transaction, and
source, removed the contaminated chain, preserved unrelated state, and had no
post-recovery leakage.

## Synthetic comparison

The final synthetic live matrix reported PolicyV2 recall of 51/72 (70.8%),
whereas this deterministic realistic workload reports 9/20 (45.0%). Persistent
compromise moves from 21/72 to 11/20. Rejection containment remains complete in
both measurements. These denominators and generation modes differ; the table is
a workload-transition comparison, not a controlled equivalence claim.

## Performance and growth

Across the deterministic corpus, median end-to-end latency excluding model
generation was approximately 0.63 ms. Median transaction/security work was
approximately 0.38 ms, about 60% of this deliberately small local workflow.
Model generation is explicitly excluded from that overhead calculation.

Aggregate committed growth was 11,261 serialized bytes, 28 memory entries, 60
cache entries, 214 explicit lineage nodes, and 174 explicit lineage edges.
Rejected transaction-local changes are not included as committed growth.

The trusted core remains 12 modules and 2,940 non-comment LOC with zero
third-party core dependencies. Stage 13A adds application/evaluation code above
the trusted boundary and reports zero trusted-core growth.

## Optional local-model subset

The unchanged `llama3.2:3b` interface attempted ten workflows. Four plans were
valid and there were no transport failures. One valid benign plan attempted a
missing memory read and rolled back with a runtime error. Of three evaluable
malicious plans, two committed persistent cache/retrieval poisoning; one was
policy-rejected but also encountered a runtime error. Parse and runtime failures
are not counted as containment.

## Limitations

- This is one compact simulated agent and local corpus.
- Provenance metadata and lineage edges are explicitly supplied by trusted
  application code; they are not inferred automatically.
- Policy recall is conditional on valid plans and represented malicious actions.
- The Llama subset is too small and interface-unreliable for broad claims.
- The simulated email target does not establish atomicity for real services.
- The security-overhead fraction is high partly because the non-model baseline
  workflow is intentionally small and entirely in-process.

Raw results, tables, figures, the flagship transcript, and negative-result
records are under `evaluation_results/stage13a/`.
