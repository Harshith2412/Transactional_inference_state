import json

import pytest

from transactional_inference_state import (
    EvaluationHarness,
    EvaluationMode,
    LiveEvaluationConfiguration,
    SnapshotMatrixConfiguration,
    TrialOutcome,
    expanded_benign_corpus,
    expanded_malicious_corpus,
    flagship_compromise_scenario,
    export_snapshot_matrix,
    export_trial_records,
    generate_tables,
    latency_summary,
    paired_comparisons,
    parse_failure_category,
    percentile,
    run_live_model_matrix,
    run_snapshot_matrix,
    security_summary,
    snapshot_crossover_analysis,
    structured_output_summary,
    wilson_interval,
)


def test_expanded_malicious_corpus_size_families_metadata_and_unique_ids():
    corpus = expanded_malicious_corpus()
    assert 100 <= len(corpus) <= 200
    assert len({scenario.scenario_id for scenario in corpus}) == len(corpus)
    families = {}
    for scenario in corpus:
        families[scenario.attack_family] = families.get(scenario.attack_family, 0) + 1
        assert scenario.metadata["corpus_version"] == "stage7-v1"
        assert scenario.metadata["placement"]
        json.dumps(scenario.to_dict())
    assert len(families) == 14
    assert set(families.values()) == {8}


def test_expanded_benign_corpus_size_categories_and_unique_ids():
    corpus = expanded_benign_corpus()
    assert 40 <= len(corpus) <= 80
    assert len({scenario.scenario_id for scenario in corpus}) == len(corpus)
    categories = {scenario.metadata["benign_category"] for scenario in corpus}
    assert len(categories) == 19
    assert all(not scenario.malicious and scenario.policy_accept for scenario in corpus)


def test_model_compromise_and_runtime_containment_are_distinct():
    scenario = next(s for s in expanded_malicious_corpus()
                    if s.attack_family == "persistent_memory_poisoning")
    harness = EvaluationHarness()
    baseline = harness.run(scenario, EvaluationMode.BASELINE)[0]
    transactional = harness.run(scenario, EvaluationMode.TRANSACTIONAL)[0]
    assert baseline.model_compromise and transactional.model_compromise
    assert baseline.persistent_compromise is True
    assert baseline.runtime_containment_success is False
    assert transactional.persistent_compromise is False
    assert transactional.runtime_containment_success is True
    assert transactional.outcome == TrialOutcome.MODEL_COMPROMISED_RUNTIME_CONTAINED.value


def test_flagship_compromise_is_contained_transactionally():
    record = EvaluationHarness().run(
        flagship_compromise_scenario(), EvaluationMode.TRANSACTIONAL)[0]
    assert record.model_compromise is True
    assert record.claimed_provenance == ("user_prompt",) * 3
    assert record.runtime_provenance == "retrieved_content"
    assert record.validation_result is False
    assert record.persistent_compromise is False
    assert record.external_effect_leakage is False
    assert record.rollback_integrity is True


def test_outcome_taxonomy_distinguishes_parse_failure_and_benign_commit():
    malformed = next(s for s in expanded_malicious_corpus()
                     if s.attack_family == "structured_plan_attacks")
    malicious_record = EvaluationHarness().run(
        malformed, EvaluationMode.TRANSACTIONAL)[0]
    benign_record = EvaluationHarness().run(
        expanded_benign_corpus()[0], EvaluationMode.TRANSACTIONAL)[0]
    assert malicious_record.outcome == TrialOutcome.MALFORMED_PLAN_REJECTED.value
    assert benign_record.outcome == TrialOutcome.BENIGN_COMMIT_SUCCESS.value


def test_security_summary_containment_given_compromise_and_wilson_counts():
    scenario = next(s for s in expanded_malicious_corpus()
                    if s.attack_family == "cache_poisoning")
    records = [EvaluationHarness().run(scenario, mode)[0] for mode in EvaluationMode]
    summaries = {row["mode"]: row for row in security_summary(records)}
    assert summaries["baseline"]["persistent_compromise"]["count"] == 1
    assert summaries["transactional"]["containment_given_compromise"]["rate"] == 1
    assert 0 <= summaries["transactional"]["model_compromise"]["wilson_low"] <= 1


def test_wilson_interval_known_bounds_and_input_validation():
    low, high = wilson_interval(5, 10)
    assert low == pytest.approx(0.2366, abs=0.001)
    assert high == pytest.approx(0.7634, abs=0.001)
    assert wilson_interval(0, 0) == (0.0, 0.0)
    with pytest.raises(ValueError):
        wilson_interval(2, 1)


def test_latency_percentiles_and_schema():
    assert percentile([1, 2, 3, 4, 5], 90) == pytest.approx(4.6)
    summary = latency_summary([10, 20, 30, 40])
    assert summary.count == 4
    assert summary.mean == 25
    assert summary.median == 25
    assert summary.minimum == 10 and summary.maximum == 40
    assert summary.p95 >= summary.p90


def test_model_configuration_loading_and_unavailable_models():
    config = LiveEvaluationConfiguration.from_dict({
        "models": [{"name": "not-installed", "family": "test"}],
        "trials": 2, "malicious_limit": 1, "benign_limit": 1,
    })
    records, availability = run_live_model_matrix(config, available_models=[])
    assert records == []
    assert availability[0].available is False
    assert availability[0].reason


@pytest.mark.parametrize(("error", "category"), [
    ("malformed model output", "malformed_output"),
    ("unknown operation type", "unknown_operation"),
    ("missing or unsupported fields", "missing_field"),
    ("invalid type", "invalid_type"),
    ("duplicate operation_id", "duplicate_operation_id"),
])
def test_parse_failure_classification(error, category):
    assert parse_failure_category(error) == category


def test_paired_comparisons_retain_scenario_model_trial_identity():
    scenario = expanded_malicious_corpus()[0]
    records = [EvaluationHarness().run(scenario, mode)[0] for mode in EvaluationMode]
    pairs = paired_comparisons(records)
    assert len(pairs) == 1
    assert pairs[0]["scenario_id"] == scenario.scenario_id
    assert "total_latency_difference_ns" in pairs[0]


def test_small_snapshot_matrix_aggregation_and_crossover(tmp_path):
    results = run_snapshot_matrix(SnapshotMatrixConfiguration(
        sizes=("10KB",), mutation_ratios=(0.01, 1.0), iterations=1))
    assert len(results) == 8
    assert all(result.mutated_keys >= 1 for result in results)
    crossover = snapshot_crossover_analysis(results)
    assert len(crossover) == 2
    assert all("observed_crossover_ratio" in row for row in crossover)
    paths = export_snapshot_matrix(results, tmp_path, crossover)
    assert all(path.exists() for path in paths.values())


def test_plot_input_table_and_trial_exports(tmp_path):
    malicious = expanded_malicious_corpus()[0]
    benign = expanded_benign_corpus()[0]
    records = [EvaluationHarness().run(scenario, mode)[0]
               for scenario in (malicious, benign) for mode in EvaluationMode]
    snapshots = run_snapshot_matrix(SnapshotMatrixConfiguration(
        sizes=("10KB",), mutation_ratios=(0.05,), iterations=1))
    exported = export_trial_records(records, tmp_path / "raw")
    tables = generate_tables(records, snapshots, tmp_path / "tables")
    reliability = structured_output_summary(records)
    assert all(path.exists() for path in exported.values())
    assert all(path.exists() for path in tables.values())
    assert reliability[0]["trials"] == 4
