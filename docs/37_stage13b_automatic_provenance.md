# Stage 13B automatic provenance propagation

Stage 13B adds a small trusted dataflow-provenance layer to the Stage 13A
realistic agent workload. It records dependencies declared by trusted runtime
operations. It does **not** infer semantic causality and does not use an LLM for
lineage inference.

## Propagation model

`ProvenanceEngine` wraps values in `TrackedValue`, containing the value,
authoritative runtime source IDs, an explicit lineage node, verification state,
and optional field-specific sources. `TransformRegistry` maps a fixed set of
operations to simple rules:

- identity/copy preserves input ancestry;
- multi-input transforms retain the union of concrete source IDs;
- field selection uses only the selected field's ancestry;
- filtering preserves ancestry for retained fields;
- memory/cache writes add write records without discarding input origins;
- later reads recover committed path provenance;
- tool results include both tool-result identity and input ancestry;
- context and effect construction combine their declared inputs.

Trust and ancestry remain separate. A trusted tool does not sanitize untrusted
input ancestry. Existing declassification changes flow permission but never
rewrites origin identity.

## Provenance gaps

Transforms outside the propagation API are represented as unverified
`UNKNOWN` values. The runtime emits `PROVENANCE_GAP` and does not reconstruct
missing ancestry. The controlled gap experiment detected 1/1 break and did not
count it as successful attribution.

## Field-level behavior

The controlled object contained independent public, poisoned authorization, and
public-metadata fields. Selecting the public field excluded poisoned ancestry;
filtering public fields retained only their own sources. Measured field-level
precision and recall were both 100%, with zero false lineage assignments. This
is a controlled structural dataflow measurement, not evidence of semantic
dependency precision.

## Realistic workload integration

The existing 20 benign and 20 malicious Stage 13A workflows were replayed under
automatic propagation. Coverage was 40/40, mean coverage 100%, with no gaps in
the instrumented corpus. Security results remained exactly unchanged:

| Metric | Stage 13A | Stage 13B automatic |
|---|---:|---:|
| Benign completion | 20/20 | 20/20 |
| PolicyV2 detection | 9/20 | 9/20 |
| Persistent compromise | 11/20 | 11/20 |
| External-effect leakage | 0/20 | 0/20 |
| Containment after rejection | 9/9 | 9/9 |

Automatic provenance improves attribution, not prevention. PolicyV1 and
PolicyV2 remain frozen.

## Cache and memory flagships

The cache flagship preserves the Stage 13A negative outcome: the poisoned cache
write is accepted and persists. A later transaction reads the cache, builds a
context, and constructs a simulated effect. Automatic root queries identify
the malicious retrieval source, Session A, and its original transaction.

The memory flagship follows malicious retrieval → summary → committed memory →
later memory read → context → simulated effect. Origin user, session,
transaction, and source are all identified. The contamination report covers the
seven controlled chain nodes, and the recovery plan invalidates the committed
memory state. The PolicyV2 miss remains visible before recovery.

## Manual versus automatic

Both modes produce correct root attribution in the comparable flagship.
Manual mode requires nine explicit application graph calls. Automatic mode
requires zero explicit graph calls and eight trusted dataflow calls. The graph
grows from five nodes/four edges/1,491 estimated bytes to nine nodes/nine
edges/3,481 bytes because automatic mode records intermediate operations.

Across the full corpus, automatic mode made 354 trusted dataflow calls and zero
explicit application lineage calls, producing 414 nodes, 374 edges, and 157,913
estimated bytes.

## Performance

Fifty deterministic iterations measured:

| Operation | Median | p95 |
|---|---:|---:|
| Manual lineage recording | 49.3 µs | 50.0 µs |
| Automatic propagation | 47.3 µs | 48.5 µs |
| Context assembly | 48.2 µs | 49.3 µs |
| Memory/cache propagation | 139.5 µs | 142.7 µs |
| Root query | 12.4 µs | 13.3 µs |

Median end-to-end no-model latency for the automatic corpus was approximately
0.914 ms. Model generation is excluded.

## Trusted boundary

Automatic propagation adds one trusted module with 147 non-comment LOC. The
trusted core therefore grows from 12 modules/2,940 LOC to 13 modules/3,087 LOC.
The agent/evaluation layer is 453 non-comment LOC under the Stage 13B accounting.
Third-party runtime dependencies remain zero.

## Limitations

- Dataflow calls express structural dependencies, not semantic causality.
- Missing instrumentation remains unknown rather than reconstructed.
- The precision experiment is a controlled field-selection case.
- The realistic workload and external effects remain simulated.
- Graph/storage growth reflects detailed intermediate nodes and may require
  later lifecycle management; no compaction or durability was added.
- Automatic provenance does not improve frozen-policy recall or compromise rate.

Raw coverage, attribution, gap, taint, performance, tables, figures, and reports
are under `evaluation_results/stage13b/`.
