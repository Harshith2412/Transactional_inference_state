# Table selection

## Main paper

1. **Stage 10 frozen held-out PolicyV1 versus PolicyV2** (`evaluation_results/stage10/tables/table_1_new_heldout.csv`): primary external-generalization evidence.
2. **Stage 11 live Llama policy results** (`evaluation_results/stage11/tables/table_3_compromise_policy_detection.csv`): exact evaluable denominators and policy recall.
3. **Forced-rejection containment** (derived directly from `paired_enforcement.json`): baseline state 57/75 and effects 24/75 versus transactional 0/75 and 0/75, with 75/75 rollback integrity.
4. **Snapshot strategy benchmark** (`evaluation_results/report/table_d_snapshot.csv`): FullCopy/Delta performance across workload cells.
5. **Live failure taxonomy** (`evaluation_results/stage11/tables/table_9_live_policy_failures.csv`): makes the six indirect-authorization misses visible.
6. **Trusted-core complexity** (`evaluation_results/stage11/tables/table_10_complexity.csv`): reports implementation scope and dependencies.

Detailed per-model interface records, parse failures, attack-family rows,
hard-benign scenarios, timing records, per-scenario outputs, and multi-turn seed
records are supplementary tables.
