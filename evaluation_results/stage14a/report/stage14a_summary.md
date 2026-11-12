# Stage 14A Summary

The frozen external manifest contains 40 adapted task concepts: 10 ASB memory
attacks plus 10 controls and 10 AgentDojo injection/tool attacks plus 10 controls.
Manifest SHA-256: `858e466e3673571f2f0a518b5125dd5e57ecd3883688f40ed22267b95777c61e`.

Combined malicious recall was 25% PolicyV2, 0% Sequence, 100% Provenance, 0%
Semantic, and 100% Hybrid. Every validator had 0/20 benign false positives on
this subset. PolicyV2 recall differed sharply: 0/10 for primary ASB memory tasks
and 5/10 for AgentDojo concepts.

Under PolicyV2, 10/10 primary malicious writes persisted and 10/10 controls
completed. Forced rejection contained 20/20 malicious adapted operations without
persistent state or simulated effects. Task-specific causal recovery correctly
identified origin and contamination, preserved unrelated state, and blocked
reuse in 10/10 accepted memory cases.

Authoritative propagation coverage was 34/40 (85%). Six sandbox operations were
honestly classified as adapter-only transforms, producing a 15% gap rate.

This is an adapted subset evaluation, not a full native execution of ASB,
AgentDojo, or MemSecBench. Trusted core growth is zero: 14 modules, 3,547 LOC,
and no third-party runtime dependencies. External adapter/reporting code is 177
LOC outside the trusted core.
