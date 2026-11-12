from copy import deepcopy

import pytest

from transactional_inference_state import (
    InferenceState,
    PolicyValidator,
    SessionManager,
    SnapshotManager,
    TransactionError,
    TransactionManager,
    run_attack_experiment,
)


def test_attack_experiment_rejects_and_exactly_restores_state():
    result = run_attack_experiment()

    assert result.rejected is True
    assert result.restored_exactly is True
    assert result.final_state == result.initial_state
    assert [event.event_type for event in result.events] == [
        "transaction_begin",
        "state_mutation",
        "validation",
        "rollback",
    ]
    assert result.events[2].details == {"accepted": False}


def test_commit_retains_mutations():
    state = InferenceState(session_memory={"count": 1})
    manager = TransactionManager(state, validator=PolicyValidator(True))

    transaction_id = manager.begin()
    state.session_memory["count"] = 2
    manager.record_mutation("increment count")
    assert manager.validate() is True
    manager.commit()

    assert transaction_id == "txn-000001"
    assert state.session_memory == {"count": 2}
    assert manager.active_transaction_id is None
    assert [event.event_type for event in manager.event_log.events] == [
        "transaction_begin",
        "state_mutation",
        "validation",
        "commit",
    ]


def test_rollback_restores_every_field_and_nested_mutation():
    state = InferenceState(
        session_memory={"nested": {"items": [1, 2]}},
        scratchpad=["safe"],
        application_cache={"a": 1},
        retrieved_data=[{"row": 1}],
        tool_results=[{"ok": True}],
        pending_memory_writes=["pending"],
        user_session_metadata={"user": "one"},
        security_state={"roles": ["reader"]},
    )
    expected = deepcopy(state)
    original_identity = id(state)
    manager = TransactionManager(state)

    manager.begin()
    state.session_memory["nested"]["items"].append(3)
    state.scratchpad.clear()
    state.application_cache["b"] = 2
    state.retrieved_data.append({"row": 2})
    state.tool_results[0]["ok"] = False
    state.pending_memory_writes.append("unsafe")
    state.user_session_metadata["user"] = "attacker"
    state.security_state["roles"].append("admin")
    manager.record_mutation("mutate all state components")
    manager.rollback()

    assert id(state) == original_identity
    assert state == expected


def test_sessions_are_independent():
    sessions = SessionManager()
    first = sessions.create_session("first")
    second = sessions.create_session("second")

    first.session_memory["private"] = "first-only"
    first.scratchpad.append("private thought")

    assert first is not second
    assert second == InferenceState()
    assert sessions.get_session("first") is first


def test_session_lifecycle_validation():
    sessions = SessionManager()
    with pytest.raises(ValueError, match="must not be empty"):
        sessions.create_session("")
    sessions.create_session("same")
    with pytest.raises(ValueError, match="already exists"):
        sessions.create_session("same")
    with pytest.raises(KeyError, match="unknown session"):
        sessions.get_session("missing")


def test_transaction_ids_are_unique_and_deterministic_per_manager():
    manager = TransactionManager(InferenceState())
    assert manager.begin() == "txn-000001"
    manager.rollback()
    assert manager.begin() == "txn-000002"


@pytest.mark.parametrize("operation", ["commit", "rollback", "validate"])
def test_operations_without_active_transaction_raise(operation):
    manager = TransactionManager(InferenceState())
    with pytest.raises(TransactionError, match="no transaction"):
        getattr(manager, operation)()


def test_nested_begin_raises_and_original_transaction_can_continue():
    manager = TransactionManager(InferenceState())
    transaction_id = manager.begin()
    with pytest.raises(TransactionError, match="already active"):
        manager.begin()
    assert manager.active_transaction_id == transaction_id
    manager.rollback()


def test_commit_before_validation_raises():
    manager = TransactionManager(InferenceState())
    manager.begin()
    with pytest.raises(TransactionError, match="must be validated"):
        manager.commit()
    manager.rollback()


def test_rejected_transaction_cannot_commit_but_can_rollback():
    state = InferenceState()
    manager = TransactionManager(state, validator=PolicyValidator(False))
    manager.begin()
    state.session_memory["unsafe"] = True
    assert manager.validate() is False
    with pytest.raises(TransactionError, match="rejected"):
        manager.commit()
    manager.rollback()
    assert state == InferenceState()


def test_callable_policy_is_deterministic_from_state():
    policy = PolicyValidator(lambda state: not state.pending_memory_writes)
    safe = InferenceState()
    unsafe = InferenceState(pending_memory_writes=["write"])
    assert policy.validate(safe) is True
    assert policy.validate(unsafe) is False


def test_snapshot_is_deep_copy_and_restore_does_not_alias_snapshot():
    snapshots = SnapshotManager()
    state = InferenceState(session_memory={"nested": [1]})
    snapshot = snapshots.create(state)
    state.session_memory["nested"].append(2)
    snapshots.restore(state, snapshot)
    state.session_memory["nested"].append(3)

    assert snapshot.session_memory == {"nested": [1]}
    assert state.session_memory == {"nested": [1, 3]}


def test_event_details_are_copied_and_event_view_is_immutable():
    manager = TransactionManager(InferenceState())
    manager.begin()
    details = {"keys": ["one"]}
    manager.record_mutation("test", payload=details)
    details["keys"].append("two")

    assert manager.event_log.events[1].details["payload"] == {"keys": ["one"]}
    assert isinstance(manager.event_log.events, tuple)

