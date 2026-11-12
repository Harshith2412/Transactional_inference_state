import pytest

from transactional_inference_state import (
    DeltaStrategy,
    EffectManager,
    EffectStatus,
    FakeEmailService,
    FullCopyStrategy,
    InferenceState,
    PartialEffectCommitError,
    PolicyValidator,
    SessionManager,
    TransactionError,
    TransactionManager,
    TransactionStatus,
    TransactionalTools,
    run_accepted_effect_experiment,
    run_concurrent_effect_experiment,
    run_partial_failure_experiment,
    run_rejected_effect_experiment,
    state_digest,
)


def setup_effect_runtime(*, accepted=True, fail_on_calls=None, strategy=None):
    sessions = SessionManager()
    sessions.create_session("A")
    sessions.create_session("B")
    service = FakeEmailService(fail_on_calls=fail_on_calls)
    effects = EffectManager(service)
    manager = TransactionManager(
        sessions, validator=PolicyValidator(accepted), effect_manager=effects,
        snapshot_strategy=strategy or FullCopyStrategy(),
    )
    return sessions, service, effects, manager


def stage_email(effects, transaction, session, subject):
    return TransactionalTools(effects, transaction, session).send_email(
        to=f"{session.lower()}@example.test", subject=subject, body="body"
    )


def test_rejected_effect_experiment_never_sends_and_restores_digest():
    result = run_rejected_effect_experiment()
    assert result.sent_count == 0
    assert result.effect_status is EffectStatus.DISCARDED
    assert result.state_equal is True
    assert result.pre_digest == result.post_digest


def test_accepted_effect_experiment_executes_once_after_commit():
    result = run_accepted_effect_experiment()
    assert result.sent_before_commit == 0
    assert result.sent_after_commit == 1
    assert result.effect_status is EffectStatus.EXECUTED


def test_multiple_effects_execute_in_sequence_order():
    _, service, effects, manager = setup_effect_runtime()
    tx = manager.begin("A")
    for subject in ("first", "second", "third"):
        stage_email(effects, tx, "A", subject)
    assert service.sent_messages == []
    manager.validate(tx)
    manager.commit(tx)
    assert [message.subject for message in service.sent_messages] == [
        "first", "second", "third"
    ]
    transaction_effects = effects.list_effects(tx, "A")
    assert [effect.sequence_number for effect in transaction_effects] == [1, 2, 3]
    assert all(effect.status is EffectStatus.EXECUTED
               for effect in transaction_effects)


def test_concurrent_effect_isolation_experiment():
    result = run_concurrent_effect_experiment()
    assert result.sent_subjects == ("B",)
    assert result.effect_a_status is EffectStatus.DISCARDED
    assert result.effect_b_status is EffectStatus.EXECUTED


def test_cross_session_cannot_stage_list_or_execute_effects():
    _, _, effects, manager = setup_effect_runtime()
    a = manager.begin("A")
    stage_email(effects, a, "A", "owned-by-A")
    with pytest.raises(TransactionError, match="does not belong"):
        stage_email(effects, a, "B", "intrusion")
    with pytest.raises(TransactionError, match="do not belong"):
        effects.list_effects(a, "B")
    manager.validate(a)
    manager.commit(a)
    with pytest.raises(TransactionError, match="do not belong"):
        effects.execute_transaction(a, "B")


@pytest.mark.parametrize("closure", ["commit", "rollback"])
def test_cannot_stage_effect_after_transaction_closure(closure):
    _, _, effects, manager = setup_effect_runtime()
    tx = manager.begin("A")
    if closure == "commit":
        manager.validate(tx)
        manager.commit(tx)
    else:
        manager.rollback(tx)
    with pytest.raises(TransactionError, match="active transaction"):
        stage_email(effects, tx, "A", "late")


def test_cannot_execute_before_commit_or_execute_twice():
    _, service, effects, manager = setup_effect_runtime()
    tx = manager.begin("A")
    stage_email(effects, tx, "A", "once")
    with pytest.raises(TransactionError, match="before transaction commit"):
        effects.execute_transaction(tx, "A")
    manager.validate(tx)
    manager.commit(tx)
    assert len(service.sent_messages) == 1
    with pytest.raises(TransactionError, match="already executed"):
        effects.execute_transaction(tx, "A")
    assert len(service.sent_messages) == 1


def test_executed_effect_cannot_be_discarded():
    _, _, effects, manager = setup_effect_runtime()
    tx = manager.begin("A")
    stage_email(effects, tx, "A", "executed")
    manager.validate(tx)
    manager.commit(tx)
    with pytest.raises(TransactionError, match="cannot be discarded"):
        effects.discard_transaction(tx, "A")


def test_partial_failure_records_executed_failed_and_unexecuted():
    result = run_partial_failure_experiment()
    assert result.executed_effects == ("effect-000001",)
    assert result.failed_effect == "effect-000002"
    assert result.unexecuted_effects == ("effect-000003",)
    assert result.transaction_status is TransactionStatus.PARTIAL_EFFECT_FAILURE


def test_partial_failure_keeps_internal_commit_and_does_not_resend_success():
    sessions, service, effects, manager = setup_effect_runtime(fail_on_calls={2})
    tx = manager.begin("A")
    manager.write_private(tx, "A", "session_memory", "committed", True)
    for subject in ("success", "failure", "not-run"):
        stage_email(effects, tx, "A", subject)
    manager.validate(tx)
    with pytest.raises(PartialEffectCommitError) as error:
        manager.commit(tx)
    assert error.value.failed_effect_id == "effect-000002"
    assert sessions.get_session("A").session_memory == {"committed": True}
    assert [message.subject for message in service.sent_messages] == ["success"]
    assert [effect.status for effect in effects.list_effects(tx, "A")] == [
        EffectStatus.EXECUTED, EffectStatus.FAILED, EffectStatus.STAGED
    ]
    with pytest.raises(TransactionError, match="closed"):
        manager.commit(tx)
    assert len(service.sent_messages) == 1


@pytest.mark.parametrize("strategy", [FullCopyStrategy(), DeltaStrategy()])
def test_state_and_effect_rollback_integrity_for_both_strategies(strategy):
    sessions, service, effects, manager = setup_effect_runtime(
        accepted=False, strategy=strategy
    )
    state = sessions.get_session("A")
    state.session_memory["profile"] = {"permissions": ["read"]}
    before = InferenceState(session_memory={"profile": {"permissions": ["read"]}})
    digest = state_digest(state)
    tx = manager.begin("A")
    profile = manager.read_private(tx, "A", "session_memory", "profile")
    profile["permissions"].append("admin")
    manager.write_private(tx, "A", "session_memory", "profile", profile)
    stage_email(effects, tx, "A", "sensitive")
    manager.validate(tx)
    manager.rollback(tx)
    assert state == before
    assert state_digest(state) == digest
    assert service.sent_messages == []
    assert effects.list_effects(tx, "A")[0].status is EffectStatus.DISCARDED


def test_effect_events_include_transaction_and_session_identity():
    _, _, effects, manager = setup_effect_runtime()
    tx = manager.begin("A")
    stage_email(effects, tx, "A", "event")
    manager.validate(tx)
    manager.commit(tx)
    effect_events = [event for event in manager.event_log.events
                     if event.event_type.startswith("EFFECT_")]
    assert [event.event_type for event in effect_events] == [
        "EFFECT_REQUESTED", "EFFECT_STAGED", "EFFECT_EXECUTED"
    ]
    assert all(event.transaction_id == tx and event.session_id == "A"
               for event in effect_events)
