# Project evolution, Stages 1–11

Test counts are historical full-suite totals, not tests added in each stage.

| Stage | Goal and major addition | Tests | Important result | Limitation exposed / reason for next stage |
|---:|---|---:|---|---|
| 1 | Test tentative inference state; added state, snapshots, lifecycle, sessions, policy stub, and events. | 15 | Unsafe mutation was rejected and exactly restored. | One active transaction and eager copying motivated isolation work. |
| 2 | Add concurrent transactions, session isolation, versioned shared cache, and optimistic conflicts. | 32 | Dirty reads were prevented and stale shared writes aborted. | Full copying remained costly. |
| 3 | Abstract snapshots; add Delta, digest checks, and benchmarks. | 52 | Both strategies preserved tested rollback integrity. | Only internal state was transactional. |
| 4 | Stage simulated external effects and define failure ordering. | 66 | Rejected email effects were discarded. | No model-produced operations. |
| 5 | Add local-model adapters, strict `ModelPlan`, operation execution, and provenance. | 86 passed, 1 skipped | Malformed plans failed closed in tested paths. | Demonstrations lacked comparative evaluation. |
| 6 | Compare immediate baseline with transactions across malicious and benign cases. | 99 passed, 1 skipped | Paired metrics separated persistence and utility. | Corpus and live sample were small. |
| 7 | Expand corpus/model matrix, statistics, snapshot matrix, reporting, and CLI. | 116 passed, 1 skipped | Produced systematic security and scaling artifacts. | Policy, corpus, model, and durability limits remained. |
| 8 | Separate model compromise, independent policy, and containment; add capabilities, provenance, budgets, failures, and multi-turn cases. | 180 passed, 1 skipped | Independent policy could be evaluated apart from rollback. | Shallow semantic rules and commit/effect durability remained. |
| 9 | Analyze misses and freeze an interpretable PolicyV2 with ablations and held-out tests. | 213 passed, 1 skipped | V2 held-out recall was 79.2% on 24 attacks. | Small held-out sets risked optimistic generalization. |
| 10 | Test frozen policies on 100 malicious/80 hard-benign cases and audit complexity. | 235 passed, 1 skipped | V2 recall fell to 70.0% and FPR rose to 12.5%. | Live plans were not sufficiently evaluable for recall. |
| 11 | Improve only the structured interface, qualify models, and run frozen live validation. | 263 passed, 1 skipped | Llama V2 recall was 69/75; all 69 rejected plans were contained. | One model qualified; six semantic authorization misses remained. |

Stage 12 freezes these outcomes rather than using them to change the system.
