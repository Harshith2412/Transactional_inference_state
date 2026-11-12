# Figure selection

## Main paper

1. **System architecture:** `research_release/figures/architecture.svg`. It answers where the trust boundary and tentative state lie and is necessary to interpret every experiment.
2. **Frozen PolicyV1 versus PolicyV2:** `evaluation_results/stage10/figures/figure_2_policy_tradeoff.svg`. It shows the held-out recall/false-positive tradeoff rather than only the favorable live result.
3. **Live security pipeline:** `evaluation_results/stage11/figures/figure_8_pipeline.svg`. It follows attempts through parsing, compromise, policy detection, and persistence, preserving the conditional denominators.
4. **Forced-rejection consequences:** `evaluation_results/stage11/figures/figure_7_persistence.svg`, accompanied by the paired-enforcement table. It isolates the containment primitive from policy accuracy.
5. **Snapshot scaling:** `evaluation_results/figures/figure_09_mutation_ratio.svg`. It compares FullCopy and Delta as mutation ratio changes and addresses the snapshot cost question.
6. **Live enforcement overhead:** `evaluation_results/stage11/figures/figure_11_overhead.svg`. It places measured transactional overhead beside local generation latency.

## Appendix candidates

Interface raw/normalized parse rates, parse-failure taxonomy, generation-mode
comparisons, per-family recall, benign utility, multi-turn results, state-size
commit/rollback curves, traced memory, detailed latency distributions, Stage
10/11 interface comparison, and all per-scenario plots belong in the appendix or
artifact. They support diagnosis but are not needed for the main argument.
