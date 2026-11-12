# Stage 13B automatic provenance

Automatic lineage captures trusted runtime dataflow, not semantic causality.

## Results

- Automatic provenance coverage: 40/40 (100.0%)
- Unknown lineage in instrumented corpus: 0.0%
- Controlled provenance-gap detection: 1/1
- Correct cache/memory origin user, session, transaction, and source: 2/2 for each dimension
- Contamination precision/recall: 100%/100% in the controlled memory chain
- Field-level precision/recall: 100.0%/100.0%
- False field lineage: 0
- Manual explicit lineage calls: 9 per flagship
- Automatic explicit lineage calls: 0; trusted dataflow calls: 8

Security outcomes are unchanged from Stage 13A: PolicyV2 detection remains 9/20, persistent compromise 11/20, benign completion 20/20, external leakage 0/20, and rejection containment 9/9. Automatic provenance improves attribution, not prevention.

The cache flagship traces the later T2 context through the committed cache to its original malicious retrieval, origin transaction, and Session A. The memory flagship traces the later effect to the original retrieval and produces a selective recovery plan while preserving the policy miss before recovery.

## Costs and growth

Automatic propagation median: 47.3 µs; p95: 48.5 µs. Context assembly median: 48.2 µs. Memory/cache propagation median: 139.5 µs. Automatic no-model corpus latency median: 0.914 ms.

The comparable flagship graph grows from 5 nodes/4 edges/1491 estimated bytes manually to 9 nodes/9 edges/3481 bytes automatically. The added detail is reported rather than hidden.

Trusted core: 13 modules, 3087 non-comment LOC. Automatic propagation adds one trusted module and 147 LOC. Third-party runtime dependencies remain zero.
