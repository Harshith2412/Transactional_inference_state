# Documentation index

This documentation covers the implemented Stages 1–11 research-freeze baseline,
the subsequent Stage 12A–12E transaction development, and measured
artifacts present in the repository. Mechanisms, observations, interpretations,
limitations, and future work are labeled separately.

Suggested reading order:

1. [Project overview](01_project_overview.md)
2. [Research problem](02_research_problem.md)
3. [Threat model](03_threat_model.md)
4. [Architecture](04_architecture.md)
5. [Transaction semantics](05_transaction_semantics.md)
6. [Concurrency and isolation](06_concurrency_and_isolation.md)
7. [Snapshot strategies](07_snapshot_strategies.md)
8. [External effects](08_external_effects.md)
9. [Model integration](09_model_integration.md)
10. [Provenance and trust](10_provenance_and_trust.md)
11. [Policy and validation](11_policy_and_validation.md)
12. [Evaluation methodology](12_evaluation_methodology.md)
13. [Metrics](13_metrics.md)
14. [Results](14_results.md)
15. [Performance analysis](15_performance_analysis.md)
16. [Structured-output reliability](16_structured_output_reliability.md)
17. [Limitations](17_limitations.md)
18. [Failure modes](18_failure_modes.md)
19. [Reproducibility](19_reproducibility.md)
20. [CLI and usage](20_cli_and_usage.md)
21. [Repository map](21_repository_map.md)
22. [Design decisions](22_design_decisions.md)
23. [Stage history](23_stage_history.md)
24. [Future work](24_future_work.md)
25. [Research claims](25_research_claims.md)
26. [Glossary](26_glossary.md)
27. [Stage 8 independent policy and robustness](27_stage8_independent_policy.md)
28. [Stage 9 policy refinement](28_stage9_policy_refinement.md)
29. [Stage 10 live-model validation](29_stage10_live_model_validation.md)
30. [Stage 11 live external validation](30_stage11_live_external_validation.md)
31. [Stage 12A provenance-aware transactions](31_stage12a_provenance_transactions.md)
32. [Stage 12B fine-grained copy-on-write state](32_stage12b_fine_grained_cow.md)
33. [Stage 12C cross-session information-flow enforcement](33_stage12c_cross_session_information_flow.md)
34. [Stage 12D selective commit and quarantine](34_stage12d_selective_commit_quarantine.md)
35. [Stage 12E delayed compromise and recovery](35_stage12e_delayed_compromise_recovery.md)
36. [Stage 13A realistic agent workload](36_stage13a_real_agent_workload.md)
37. [Stage 13B automatic provenance propagation](37_stage13b_automatic_provenance.md)
38. [Stage 13C independent validator comparison](38_stage13c_validator_comparison.md)
39. [Stage 13D durability and recovery](39_stage13d_durability_recovery.md)
40. [Stage 13E concurrent session scale](40_stage13e_concurrency_scale.md)
41. [Stage 14A external benchmark validation](41_stage14a_external_benchmark_validation.md)
42. [Stage 14B provenance and authority laundering](42_stage14b_provenance_authority_laundering.md)
43. [Stage 15A external checkpoint feasibility](43_stage15a_external_checkpoint_feasibility.md)
44. [Stage 15A Linux checkpoint results](44_stage15a_linux_checkpoint_results.md)
45. [Stage 15A.2 CRIU reliability](45_stage15a2_criu_reliability.md)
46. [Stage 15A.3 scoped external participants](46_stage15a3_scoped_external_participants.md)
47. [Stage 15B external transaction integration](47_stage15b_external_transaction_integration.md)
48. [Exact execution path and current trust boundaries](48_exact_execution_path.md)
49. [Executable end-to-end transaction traces](49_end_to_end_transaction_trace.md)
50. [Minimal Redis transactional adapter design](50_redis_transactional_adapter_design.md)
51. [Redis transactional adapter implementation](51_redis_transactional_adapter_implementation.md)
52. [Redis transactional participant evaluation](52_redis_transactional_participant_evaluation.md)
53. [System architecture for review](53_system_architecture_for_review.md)

Implementation lives in [`src/transactional_inference_state/`](../src/transactional_inference_state/).
Tests live in [`tests/`](../tests/). Raw evaluations, tables, reports, and figures
live in [`evaluation_results/`](../evaluation_results/), especially the
[Stage 7 summary](../evaluation_results/report/evaluation_summary.md),
[limitations](../evaluation_results/report/limitations.md),
[tables](../evaluation_results/report/tables.md), and
[figures](../evaluation_results/figures/). The original
[`TRUST_BOUNDARY.md`](../TRUST_BOUNDARY.md) is preserved and complemented here.
Stage 8 artifacts are under
[`evaluation_results/stage8/`](../evaluation_results/stage8/).
Stage 9 held-out, ablation, and live artifacts are under
[`evaluation_results/stage9/`](../evaluation_results/stage9/).
Stage 10 external-validation artifacts are under
[`evaluation_results/stage10/`](../evaluation_results/stage10/).
Stage 11 artifacts are under
[`evaluation_results/stage11/`](../evaluation_results/stage11/).
Stage 12A results are under
[`evaluation_results/stage12a/`](../evaluation_results/stage12a/).
Stage 12B results are under
[`evaluation_results/stage12b/`](../evaluation_results/stage12b/).
Stage 12C results are under
[`evaluation_results/stage12c/`](../evaluation_results/stage12c/).
Stage 12D results are under
[`evaluation_results/stage12d/`](../evaluation_results/stage12d/).
Stage 12E results are under
[`evaluation_results/stage12e/`](../evaluation_results/stage12e/).
Stage 13A realistic-agent results are under
[`evaluation_results/stage13a/`](../evaluation_results/stage13a/).
Stage 13B automatic-provenance results are under
[`evaluation_results/stage13b/`](../evaluation_results/stage13b/).
Stage 13C validator-comparison results are under
[`evaluation_results/stage13c/`](../evaluation_results/stage13c/).
Stage 13D durability/recovery results are under
[`evaluation_results/stage13d/`](../evaluation_results/stage13d/).
Stage 13E concurrency-scale results are under
[`evaluation_results/stage13e/`](../evaluation_results/stage13e/).
Stage 14A external-validation results are under
[`evaluation_results/stage14a/`](../evaluation_results/stage14a/).
Stage 14B laundering and authority results are under
[`evaluation_results/stage14b/`](../evaluation_results/stage14b/).
Stage 15A checkpoint-feasibility results are under
[`evaluation_results/stage15a/`](../evaluation_results/stage15a/).
Stage 15B scoped external-transaction results are under
[`evaluation_results/stage15b/`](../evaluation_results/stage15b/).
