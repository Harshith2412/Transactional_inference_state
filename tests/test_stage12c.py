from dataclasses import FrozenInstanceError

import pytest

import transactional_inference_state as tis
from transactional_inference_state import stage12c


def test_same_session_flow_is_allowed():
    fixture = stage12c._base_fixture()
    source = (fixture.source_ids["private_token"],)
    decision = fixture.policy.evaluate(
        current=fixture.principal_a,
        scope=tis.FlowResourceScope("profile", "private.SA"),
        source_ids=source,
    )
    assert decision.allowed
    assert decision.outcome is tis.FlowOutcome.FLOW_ALLOWED


def test_same_user_cross_session_private_flow_is_denied():
    fixture = stage12c._base_fixture()
    fixture.sessions.create_session("SA2", user_id="A")
    decision = fixture.policy.evaluate(
        current=tis.SecurityPrincipal("A", "SA2"),
        scope=tis.FlowResourceScope("profile", "private.SA2"),
        source_ids=(fixture.source_ids["private_token"],),
    )
    assert not decision.allowed
    assert decision.outcome is tis.FlowOutcome.FLOW_DENIED_CROSS_SESSION


def test_cross_user_flow_is_denied():
    fixture = stage12c._base_fixture()
    decision = fixture.policy.evaluate(
        current=fixture.principal_b,
        scope=tis.FlowResourceScope("profile", "shared.profile.private_token"),
        source_ids=(fixture.source_ids["private_token"],),
    )
    assert not decision.allowed
    assert decision.outcome is tis.FlowOutcome.FLOW_DENIED_CROSS_USER


def test_public_system_field_is_allowed():
    fixture = stage12c._base_fixture()
    decision = fixture.policy.evaluate(
        current=fixture.principal_b,
        scope=tis.FlowResourceScope("profile", "shared.profile.weather"),
        source_ids=(fixture.source_ids["weather"],),
    )
    assert decision.allowed
    assert decision.outcome is tis.FlowOutcome.FLOW_PUBLIC_FIELD_ALLOWED


def test_mixed_field_filtering_returns_only_public_field():
    result = tis.flagship_flow_experiment()
    assert result.before_value == {"weather": "sunny"}
    assert result.before_outcomes["private_token"] == "FLOW_DENIED_CROSS_USER"
    assert result.restricted_fields_leaked == 0


def test_declassification_allows_one_field_and_preserves_provenance():
    result = tis.flagship_flow_experiment()
    assert result.after_value == {"display_name": "Alice", "weather": "sunny"}
    assert result.after_outcomes["display_name"] == "FLOW_DECLASSIFIED"
    assert result.after_outcomes["private_token"] == "FLOW_DENIED_CROSS_USER"
    assert result.provenance_unchanged


def test_invalid_declassification_is_rejected():
    fixture = stage12c._base_fixture()
    with pytest.raises(KeyError):
        fixture.declassifications.issue(
            source_id="model-invented", source_session="SA",
            destination_scope="shared.any", reason="fake", issuer="model",
        )
    with pytest.raises(ValueError, match="does not match"):
        fixture.declassifications.issue(
            source_id=fixture.source_ids["private_token"], source_session="SB",
            destination_scope="shared.any", reason="wrong session", issuer="runtime",
        )


def test_declassification_record_is_immutable_and_logged():
    fixture = stage12c._base_fixture()
    rule = fixture.declassifications.issue(
        source_id=fixture.source_ids["display_name"], source_session="SA",
        destination_scope="shared.profile.display_name", reason="approved",
        issuer="reviewer",
    )
    with pytest.raises(FrozenInstanceError):
        rule.reason = "changed"
    assert any(event.event_type == "DECLASSIFICATION_ISSUED"
               for event in fixture.manager.event_log.events)


def test_missing_provenance_fails_closed_and_label_stripping_does_not_leak():
    result = tis.label_stripping_experiment()
    assert result.raw_value_stored
    assert result.outcome == "FLOW_DENIED_MISSING_PROVENANCE"
    assert not result.allowed and not result.leaked


def test_provenance_laundering_remains_rooted_in_session_a():
    result = tis.laundering_experiment()
    assert len(result.chain_source_ids) == 4
    assert result.root_users == ("A",)
    assert result.root_sessions == ("SA",)
    assert result.root_transactions
    assert result.outcome == "FLOW_DENIED_CROSS_USER"
    assert not result.leaked


def test_source_mixing_retains_private_and_public_roots_and_denies():
    fixture = stage12c._base_fixture()
    decision = stage12c._mixed_source_attempt(fixture)
    assert not decision.allowed
    assert set(decision.origin_users) == {"A", "system"}
    assert set(decision.origin_sessions) == {"SA", "PUBLIC"}


def test_capability_is_bound_to_user_session_and_scope():
    fixture = stage12c._base_fixture()
    policy = tis.FlowPolicy(
        fixture.manager.provenance_registry, fixture.declassifications,
        require_capability=True,
    )
    source = (fixture.source_ids["weather"],)
    valid = tis.FlowCapability(
        "shared.read", "B", "SB", frozenset({"shared.profile.weather"})
    )
    allowed = policy.evaluate(
        current=fixture.principal_b,
        scope=tis.FlowResourceScope("profile", "shared.profile.weather"),
        source_ids=source, capability=valid,
    )
    assert allowed.allowed
    stolen = policy.evaluate(
        current=fixture.principal_b,
        scope=tis.FlowResourceScope("profile", "shared.profile.weather"),
        source_ids=source,
        capability=tis.FlowCapability(
            "shared.read", "A", "SA", frozenset({"shared.profile.weather"})
        ),
    )
    assert stolen.outcome is tis.FlowOutcome.FLOW_DENIED_CAPABILITY_SCOPE


def test_shared_cache_collision_preserves_origin_and_blocks_b():
    fixture = stage12c._base_fixture()
    decision = stage12c._write_and_attempt(
        fixture, "collision", tis.RuntimeSourceType.MEMORY
    )
    assert not decision.allowed
    assert decision.origin_sessions == ("SA",)


def test_dirty_cross_session_read_is_prevented_before_flow_policy():
    fixture = stage12c._base_fixture()
    assert stage12c._dirty_read_prevented(fixture)


def test_flow_attack_corpus_has_no_unauthorized_leaks_or_false_blocks():
    trials = tis.run_flow_attack_corpus()
    assert len(trials) >= 10
    assert not any(trial.leaked for trial in trials)
    assert not any(trial.false_block for trial in trials)
    assert {trial.attack_family for trial in trials} >= {
        "dirty_cross_session_read", "provenance_laundering",
        "label_stripping", "source_mixing", "mixed_field_json",
    }


def test_root_origin_queries_traverse_multi_parent_lineage():
    fixture = stage12c._base_fixture()
    transaction = fixture.manager.begin("SA")
    derived = fixture.manager.issue_provenance(
        transaction, tis.RuntimeSourceType.DERIVED_VALUE,
        trust_label=tis.TrustLabel.MIXED,
        parent_source_ids=(fixture.source_ids["display_name"],
                           fixture.source_ids["weather"]),
    )
    registry = fixture.manager.provenance_registry
    assert registry.origin_users((derived.source_id,)) == ("A", "system")
    assert registry.origin_sessions((derived.source_id,)) == ("PUBLIC", "SA")
    assert set(registry.origin_sources((derived.source_id,))) == {
        fixture.source_ids["display_name"], fixture.source_ids["weather"]
    }
    fixture.manager.rollback(transaction)


def test_actual_concurrent_flow_attempt_blocks_every_private_field():
    result = tis.run_concurrency_stress((10,))[0]
    assert result.sessions == 10
    assert result.blocked_flows == 10
    assert result.unauthorized_flows_allowed == 0
    assert result.allowed_declassified_flows == 10
    assert result.public_flows_allowed == 10
    assert result.valid_flows_false_blocked == 0
    assert result.rollback_integrity
    assert result.conflict_aborts == 9


def test_concurrent_rollback_does_not_change_shared_profile():
    fixture = stage12c._base_fixture()
    before = fixture.manager.shared_state.read("profile")
    tis.run_concurrency_stress((10,))
    after = fixture.manager.shared_state.read("profile")
    assert before == after


def test_field_flow_events_are_distinct_from_transaction_status():
    fixture = stage12c._base_fixture()
    stage12c._read_profile(fixture)
    event_types = {event.event_type for event in fixture.manager.event_log.events}
    assert "FLOW_DENIED_CROSS_USER" in event_types
    assert "FLOW_PUBLIC_FIELD_ALLOWED" in event_types
    assert "rollback" in event_types


def test_flow_overhead_schema_records_all_decision_modes():
    result = tis.benchmark_flow_overhead(20)
    assert result.iterations == 20
    assert result.baseline_field_read_median_ns > 0
    assert result.provenance_field_read_median_ns > 0
    assert result.same_session_check_median_ns > 0
    assert result.cross_session_denied_median_ns > 0
    assert result.cross_session_declassified_median_ns > 0
