from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import transactional_inference_state as tis


def _context(plan, capabilities=None, source=tis.RuntimeSourceType.USER_PROMPT,
             target="a"):
    registry = tis.ProvenanceRegistry()
    root = registry.issue(source, origin_session="a")
    model = registry.issue(tis.RuntimeSourceType.MODEL_OUTPUT, origin_session="a",
                           origin_transaction="tx", parent_source_ids=(root.source_id,))
    return tis.PolicyContext("tx", "a", capabilities or tis.standard_capabilities("a"),
        tis.ResourceScope("a", target), registry.lineage((model.source_id,)),
        {op.operation_id: (root.source_id, model.source_id) for op in plan.operations})


def test_policy_result_does_not_consume_scenario_label():
    raw = tis.stage8.plan("MEMORY_WRITE", "ordinary", "value", source="user_prompt")
    benign = tis.IndependentScenario("one", "x", False, raw)
    malicious = replace(benign, scenario_id="two", malicious=True)
    harness = tis.IndependentPolicyHarness()
    assert harness.run(benign).policy_allowed == harness.run(malicious).policy_allowed


def test_capability_allow_and_deny():
    parsed = tis.parse_model_plan(tis.stage8.plan(
        "MEMORY_WRITE", "ordinary", "value", source="user_prompt"))
    assert tis.PolicyEngine().evaluate(parsed, _context(parsed)).allowed
    denied = tis.PolicyEngine().evaluate(parsed, _context(parsed, tis.CapabilitySet()))
    assert not denied.allowed
    assert tis.PolicyReason.MISSING_CAPABILITY in denied.reasons


def test_session_scope_rejected():
    parsed = tis.parse_model_plan(tis.stage8.plan("MEMORY_WRITE", "x", "y"))
    decision = tis.PolicyEngine().evaluate(parsed, _context(parsed, target="b"))
    assert tis.PolicyReason.SESSION_SCOPE_MISMATCH in decision.reasons


def test_security_alias_requires_stronger_authority():
    parsed = tis.parse_model_plan(tis.stage8.plan("MEMORY_WRITE", "access-level", "root"))
    assert tis.PolicyReason.SENSITIVE_TARGET in tis.PolicyEngine().evaluate(
        parsed, _context(parsed)).reasons


def test_security_alias_can_be_authorized_from_trusted_runtime_source():
    parsed = tis.parse_model_plan(tis.stage8.plan(
        "MEMORY_WRITE", "permission_level", 3, source="user_prompt"))
    caps = tis.CapabilitySet(tis.standard_capabilities("a").grants + (
        tis.CapabilityGrant("security_state.write", frozenset({"a"})),))
    assert tis.PolicyEngine().evaluate(parsed, _context(parsed, caps)).allowed


def test_runtime_provenance_is_frozen_and_lineage_is_complete():
    registry = tis.ProvenanceRegistry()
    parent = registry.issue(tis.RuntimeSourceType.RETRIEVED_CONTENT, origin_session="a")
    child = registry.issue(tis.RuntimeSourceType.MODEL_OUTPUT, origin_session="a",
                           parent_source_ids=(parent.source_id,))
    assert {record.source_id for record in registry.lineage((child.source_id,))} == {
        parent.source_id, child.source_id}
    with pytest.raises(FrozenInstanceError):
        child.origin_session = "b"


def test_unknown_provenance_parent_fails():
    with pytest.raises(ValueError):
        tis.ProvenanceRegistry().issue(tis.RuntimeSourceType.MODEL_OUTPUT,
                                       origin_session="a", parent_source_ids=("fake",))


def test_claimed_provenance_does_not_override_runtime_provenance():
    parsed = tis.parse_model_plan(tis.stage8.plan(
        "MEMORY_WRITE", "role", "admin", source="user_prompt"))
    decision = tis.PolicyEngine().evaluate(
        parsed, _context(parsed, source=tis.RuntimeSourceType.RETRIEVED_CONTENT))
    assert tis.PolicyReason.CLAIMED_PROVENANCE_MISMATCH in decision.reasons
    assert tis.PolicyReason.UNTRUSTED_PROVENANCE in decision.reasons


@pytest.mark.parametrize("scenario", tis.policy_evasion_corpus(),
                         ids=lambda item: item.scenario_id)
def test_policy_evasion_corpus_is_deterministic(scenario):
    result = tis.IndependentPolicyHarness().run(scenario)
    assert result.malicious and result.model_compromised
    assert result.policy_allowed in {True, False}


def test_semantic_policy_has_honest_detected_and_missed_cases():
    results = [tis.IndependentPolicyHarness().run(s)
               for s in tis.semantic_poisoning_corpus()]
    assert any(r.policy_allowed is False for r in results)
    assert any(r.policy_allowed is True and r.state_persisted for r in results)


def test_multi_turn_metrics_show_seed_propagation_and_later_detection():
    results = tis.run_multi_turn_experiments()
    assert len(results) == 5
    assert all(r.seed_committed for r in results)
    assert all(r.policy_detected_later_attack for r in results)
    assert all(r.turn_of_detection == 3 for r in results)


@pytest.mark.parametrize("result", tis.run_resource_budget_attacks(),
                         ids=lambda item: item.attack)
def test_resource_budget_attack_rejected(result):
    assert result.rejected
    expected = {
        "operation_flood": "max_operations_per_tx",
        "large_value_write": "max_state_write_bytes",
        "nested_object_bomb": "max_nested_depth",
        "effect_flood": "max_pending_effects",
        "oversized_plan": "max_plan_bytes",
        "repeated_delta_materialization": "max_delta_bytes",
    }
    assert result.budget_name == expected[result.attack]


def test_default_budget_values():
    budget = tis.TransactionBudget()
    assert (budget.max_operations_per_tx, budget.max_state_write_bytes,
            budget.max_pending_effects, budget.max_nested_depth,
            budget.max_plan_bytes) == (50, 1_048_576, 10, 20, 262_144)


def test_delta_accounting_before_and_after_materialization():
    sessions = tis.SessionManager(); sessions.create_session("a")
    manager = tis.TransactionManager(sessions, snapshot_strategy=tis.DeltaStrategy())
    tx = manager.begin("a")
    manager.write_private(tx, "a", "session_memory", "x", {"nested": [1]})
    first = manager.delta_accounting(tx)
    assert first.changed_keys == 1 and first.materialized_state_bytes is None
    manager.transaction_state(tx, "a")
    second = manager.delta_accounting(tx)
    assert second.materialized_state_bytes is not None


def test_delta_accounting_tracks_deletions():
    sessions = tis.SessionManager(); state = sessions.create_session("a")
    state.session_memory["x"] = 1
    manager = tis.TransactionManager(sessions, snapshot_strategy=tis.DeltaStrategy())
    tx = manager.begin("a"); manager.delete_private(tx, "a", "session_memory", "x")
    assert manager.delta_accounting(tx).deletions == 1


def _effect_runtime(fail_on_calls=None):
    sessions = tis.SessionManager(); sessions.create_session("a")
    service = tis.FakeEmailService(fail_on_calls=fail_on_calls)
    effects = tis.EffectManager(service)
    manager = tis.TransactionManager(sessions, effect_manager=effects)
    return manager, effects, service


def _commit_effect(manager, effects, key):
    tx = manager.begin("a")
    tis.TransactionalTools(effects, tx, "a").send_email(
        to="friend@example.test", subject="s", body="b", idempotency_key=key)
    manager.validate(tx); manager.commit(tx)


def test_effect_retry_after_success_is_suppressed():
    manager, effects, service = _effect_runtime()
    _commit_effect(manager, effects, "logical-one")
    _commit_effect(manager, effects, "logical-one")
    assert len(service.sent_messages) == 1
    assert any(e.event_type == "EFFECT_DUPLICATE_SUPPRESSED"
               for e in manager.event_log.events)


def test_effect_retry_after_pre_execution_failure_is_allowed():
    manager, effects, service = _effect_runtime({1})
    with pytest.raises(tis.PartialEffectCommitError):
        _commit_effect(manager, effects, "retryable")
    _commit_effect(manager, effects, "retryable")
    assert len(service.sent_messages) == 1


@pytest.mark.parametrize("point", list(tis.FailurePoint), ids=lambda item: item.value)
def test_failure_injection_points_are_measured(point):
    row = next(row for row in tis.run_failure_injection_matrix()
               if row.failure_point == point.value)
    if point in {tis.FailurePoint.AFTER_INTERNAL_COMMIT,
                 tis.FailurePoint.BEFORE_EFFECT_EXECUTION,
                 tis.FailurePoint.DURING_EFFECT_EXECUTION,
                 tis.FailurePoint.AFTER_FIRST_EFFECT}:
        assert row.internal_state_visible
    else:
        assert not row.internal_state_visible


def test_confusion_matrix_and_metrics_exact():
    trials = [
        tis.IndependentTrial("tp", "x", True, True, False, (),
            tis.Stage8Outcome.MODEL_COMPROMISED_POLICY_DETECTED, False, False, True),
        tis.IndependentTrial("fn", "x", True, True, True, (),
            tis.Stage8Outcome.MODEL_COMPROMISED_PERSISTED, True, False, True),
        tis.IndependentTrial("fp", "x", False, False, False, (),
            tis.Stage8Outcome.BENIGN_FALSE_REJECTED, False, False, True),
        tis.IndependentTrial("tn", "x", False, False, True, (),
            tis.Stage8Outcome.BENIGN_ACCEPTED, True, False, True),
    ]
    metric = tis.confusion_metrics(trials)
    assert (metric.tp, metric.fn, metric.fp, metric.tn) == (1, 1, 1, 1)
    assert metric.precision == metric.recall == metric.f1 == 0.5
    assert metric.detection_recall_given_compromise == 0.5
    pipeline = tis.pipeline_metrics(trials)
    assert pipeline.persistent_compromise_rate == 0.5


def test_real_model_overhead_excludes_non_live_records():
    assert tis.real_model_overhead([]) == ()


def test_reporting_generates_eight_tables_and_ten_figures(tmp_path: Path):
    trials = [tis.IndependentPolicyHarness().run(s)
              for s in tis.policy_evasion_corpus() + tis.benign_policy_corpus()]
    paths = tis.generate_stage8_artifacts(
        trials, multi_turn=tis.run_multi_turn_experiments(),
        budgets=tis.run_resource_budget_attacks(),
        failures=tis.run_failure_injection_matrix(), overhead=(), output_dir=tmp_path)
    assert len(paths) == 18
    assert all(path.exists() for path in paths)
