import csv
import json

import pytest

from transactional_inference_state import (
    EvaluationHarness,
    EvaluationMode,
    EvaluationScenario,
    FullCopyStrategy,
    aggregate_results,
    benign_corpus,
    compare_snapshot_strategies,
    export_results,
    malicious_corpus,
    provenance_spoofing_scenario,
)


def test_scenarios_are_serializable_and_loadable():
    scenario = malicious_corpus()[0]
    encoded = json.dumps(scenario.to_dict(), sort_keys=True)
    loaded = EvaluationScenario.from_dict(json.loads(encoded))
    assert loaded == scenario


def test_corpora_cover_required_families_and_benign_categories():
    malicious = malicious_corpus()
    families = {scenario.attack_family for scenario in malicious}
    assert len(malicious) >= 20
    assert families == {
        "indirect_prompt_injection", "persistent_memory_poisoning",
        "security_state_manipulation", "cache_poisoning",
        "cross_session_mutation", "email_exfiltration",
        "malformed_model_plan", "provenance_spoofing",
        "mixed_operations", "shared_state_manipulation",
    }
    benign_categories = {item.metadata["benign_category"] for item in benign_corpus()}
    assert benign_categories == {
        "memory-write", "memory-read", "cache-read", "cache-write",
        "email", "multiple", "concurrent-sessions",
    }


def test_baseline_immediately_applies_rejected_memory_poisoning():
    scenario = next(item for item in malicious_corpus()
                    if item.attack_family == "persistent_memory_poisoning")
    record = EvaluationHarness().run(scenario, EvaluationMode.BASELINE)[0]
    assert record.parser_success is True
    assert record.validation_result is False
    assert record.transaction_status == "baseline_rejected_after_apply"
    assert record.persistent_state_contamination is True


def test_transactional_mode_contains_same_memory_poisoning():
    scenario = next(item for item in malicious_corpus()
                    if item.attack_family == "persistent_memory_poisoning")
    record = EvaluationHarness().run(scenario, EvaluationMode.TRANSACTIONAL)[0]
    assert record.validation_result is False
    assert record.transaction_status == "rolled_back"
    assert record.persistent_state_contamination is False
    assert record.rollback_integrity is True


def test_baseline_email_leaks_while_transactional_email_is_discarded():
    scenario = next(item for item in malicious_corpus()
                    if item.attack_family == "email_exfiltration")
    baseline = EvaluationHarness().run(scenario, EvaluationMode.BASELINE)[0]
    transactional = EvaluationHarness().run(scenario, EvaluationMode.TRANSACTIONAL)[0]
    assert baseline.external_effect_executed is True
    assert transactional.external_effect_executed is False
    assert transactional.rollback_integrity is True


def test_benign_scenarios_complete_in_both_modes():
    harness = EvaluationHarness()
    records = [harness.run(scenario, mode)[0]
               for scenario in benign_corpus()
               for mode in EvaluationMode]
    assert all(record.benign_completion for record in records)
    assert all(record.expected_state_update_correct for record in records)
    assert all(record.expected_effect_execution_correct for record in records)


def test_concurrent_benign_scenario_opens_two_transactions():
    scenario = next(item for item in benign_corpus()
                    if item.metadata["benign_category"] == "concurrent-sessions")
    record = EvaluationHarness().run(scenario, EvaluationMode.TRANSACTIONAL)[0]
    assert scenario.metadata["peer_session"] == "peer"
    assert record.transaction_status == "committed"
    assert record.benign_completion is True


def test_aggregate_metrics_compute_distinct_security_and_utility_rates():
    harness = EvaluationHarness()
    scenarios = malicious_corpus() + benign_corpus()
    records = [harness.run(scenario, mode)[0]
               for scenario in scenarios for mode in EvaluationMode]
    aggregates = {item.mode: item for item in aggregate_results(records)}
    assert aggregates["transactional"].persistent_contamination_rate == 0
    assert aggregates["transactional"].external_side_effect_leakage_rate == 0
    assert aggregates["transactional"].attack_containment_rate == 1
    assert aggregates["transactional"].rollback_integrity_rate == 1
    assert aggregates["transactional"].false_rejection_rate == 0
    assert aggregates["transactional"].benign_completion_rate == 1
    assert aggregates["baseline"].persistent_contamination_rate > 0
    assert aggregates["baseline"].external_side_effect_leakage_rate > 0


def test_provenance_spoofing_uses_runtime_observation_for_rejection():
    scenario = provenance_spoofing_scenario()
    record = EvaluationHarness().run(scenario, EvaluationMode.TRANSACTIONAL)[0]
    assert record.claimed_provenance == ("user_prompt", "user_prompt")
    assert record.runtime_provenance == "retrieved_content"
    assert record.validation_result is False
    assert record.persistent_state_contamination is False
    assert record.external_effect_executed is False
    assert record.rollback_integrity is True


def test_performance_record_has_all_required_nonnegative_phases():
    record = EvaluationHarness().run(
        benign_corpus()[0], EvaluationMode.TRANSACTIONAL
    )[0]
    values = record.performance.__dict__
    assert set(values) == {
        "model_generation_ns", "parsing_ns", "transaction_begin_ns",
        "operation_execution_ns", "validation_ns", "commit_ns", "rollback_ns",
        "effect_execution_ns", "transaction_runtime_ns", "total_runtime_ns",
    }
    assert all(value >= 0 for value in values.values())
    assert values["total_runtime_ns"] >= values["model_generation_ns"]


def test_repeated_trials_are_recorded_independently():
    records = EvaluationHarness().run(
        benign_corpus()[0], EvaluationMode.TRANSACTIONAL, trials=3
    )
    assert [record.trial for record in records] == [1, 2, 3]


def test_csv_and_json_exports_reproduce_raw_and_aggregate_results(tmp_path):
    harness = EvaluationHarness()
    records = [harness.run(benign_corpus()[0], mode)[0]
               for mode in EvaluationMode]
    aggregates = aggregate_results(records)
    paths = export_results(records, aggregates, tmp_path)
    raw_json = json.loads(paths["raw_json"].read_text())
    aggregate_json = json.loads(paths["aggregate_json"].read_text())
    with paths["raw_csv"].open(newline="") as stream:
        raw_csv = list(csv.DictReader(stream))
    assert len(raw_json) == len(raw_csv) == 2
    assert len(aggregate_json) == 2
    assert {item["mode"] for item in raw_json} == {"baseline", "transactional"}


def test_snapshot_strategy_comparison_reuses_benchmark_schema():
    results = compare_snapshot_strategies(
        iterations=1, target_bytes=1024, mutation_ratio=0.1
    )
    assert {(result.strategy, result.operation_type) for result in results} == {
        ("full_copy", "commit"), ("full_copy", "rollback"),
        ("delta", "commit"), ("delta", "rollback"),
    }
    assert all(result.rollback_integrity for result in results)
