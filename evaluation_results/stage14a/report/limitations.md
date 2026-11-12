# Stage 14A Limitations

- This is an adapted subset, not native execution of either full benchmark.
- The adapter replaces upstream vector memory and sandbox tools with local
  runtime equivalents.
- Six operations are adapter-only transforms and lower provenance coverage.
- Deterministic plans omit model-generation and parsing variability.
- Provenance labels are authoritative in this runtime, favoring provenance-aware
  validators compared with deployments that lose labels.
- Benchmark families have different distributions; cross-workload comparisons
  are descriptive.
- No live Llama subset was run, and no external service was contacted.
- Ten causal recovery cases do not establish universal recovery.
