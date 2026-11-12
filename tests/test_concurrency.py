import pytest

from transactional_inference_state import (
    InferenceState,
    PolicyValidator,
    SessionManager,
    SharedState,
    TransactionError,
    TransactionManager,
    TransactionStatus,
    WriteConflictError,
    run_dirty_read_experiment,
    run_write_conflict_experiment,
)


def make_manager(*, validator=True, shared=None):
    sessions = SessionManager()
    sessions.create_session("A")
    sessions.create_session("B")
    manager = TransactionManager(
        sessions,
        validator=PolicyValidator(validator),
        shared_state=shared,
    )
    return sessions, manager


def test_multiple_transactions_are_active_and_individually_addressable():
    _, manager = make_manager()
    a = manager.begin("A")
    b = manager.begin("B")
    assert a != b
    assert manager.status(a) is TransactionStatus.ACTIVE
    assert manager.status(b) is TransactionStatus.ACTIVE
    assert manager.active_transaction_id is None
    with pytest.raises(TransactionError, match="transaction_id is required"):
        manager.validate()


def test_session_cannot_access_or_mutate_another_sessions_transaction():
    sessions, manager = make_manager()
    sessions.get_session("B").session_memory["secret"] = "B-only"
    b = manager.begin("B")
    with pytest.raises(TransactionError, match="does not belong"):
        manager.transaction_state(b, "A")
    with pytest.raises(TransactionError, match="does not belong"):
        manager.mutate(b, "A", lambda state: state.session_memory.clear())
    assert sessions.get_session("B").session_memory == {"secret": "B-only"}


def test_rollback_a_does_not_affect_b_and_b_commit_survives():
    sessions, manager = make_manager(
        validator=lambda state: not state.security_state.get("reject", False)
    )
    a, b = manager.begin("A"), manager.begin("B")
    manager.mutate(a, "A", lambda state: state.session_memory.update(a="tentative"))
    manager.mutate(a, "A", lambda state: state.security_state.update(reject=True))
    manager.mutate(b, "B", lambda state: state.session_memory.update(b="committed"))
    assert manager.validate(a) is False
    manager.rollback(a)
    assert manager.validate(b) is True
    manager.commit(b)
    assert sessions.get_session("A") == InferenceState()
    assert sessions.get_session("B").session_memory == {"b": "committed"}
    assert manager.status(a) is TransactionStatus.ROLLED_BACK
    assert manager.status(b) is TransactionStatus.COMMITTED


def test_nested_mutable_state_is_unchanged_after_rollback():
    sessions, manager = make_manager()
    sessions.get_session("A").session_memory["profile"] = {"permissions": ["read"]}
    transaction = manager.begin("A")
    manager.mutate(
        transaction,
        "A",
        lambda state: state.session_memory["profile"]["permissions"].append("admin"),
    )
    manager.rollback(transaction)
    assert sessions.get_session("A").session_memory["profile"]["permissions"] == ["read"]


def test_dirty_read_experiment():
    result = run_dirty_read_experiment()
    assert result.committed_before == "user"
    assert result.transaction_a_tentative == "admin"
    assert result.transaction_b_observed == "user"
    assert result.dirty_read_prevented is True


def test_transaction_reads_own_tentative_shared_write():
    shared = SharedState({"role": "user"})
    _, manager = make_manager(shared=shared)
    a = manager.begin("A")
    manager.write_shared(a, "role", "admin")
    assert manager.read_shared(a, "role") == "admin"
    assert shared.read("role").value == "user"


def test_write_conflict_aborts_stale_writer_without_overwrite():
    result = run_write_conflict_experiment()
    assert result.initial_version == 0
    assert result.committed_value == "admin"
    assert result.committed_version == 1
    assert result.second_status is TransactionStatus.ABORTED
    assert result.conflict_detected is True


def test_conflict_event_contains_transaction_session_and_keys():
    shared = SharedState({"key": 0})
    _, manager = make_manager(shared=shared)
    a, b = manager.begin("A"), manager.begin("B")
    for tx, value in ((a, 1), (b, 2)):
        manager.read_shared(tx, "key")
        manager.write_shared(tx, "key", value)
        manager.validate(tx)
    manager.commit(a)
    with pytest.raises(WriteConflictError):
        manager.commit(b)
    conflict = [e for e in manager.event_log.events
                if e.event_type == "conflict_detection"][0]
    assert conflict.transaction_id == b
    assert conflict.session_id == "B"
    assert conflict.details == {"keys": ["key"], "outcome": "aborted"}


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("commit", "commit"),
        ("rollback", "rollback"),
        ("commit", "rollback"),
        ("rollback", "commit"),
        ("commit", "mutate"),
        ("rollback", "mutate"),
        ("commit", "validate"),
        ("rollback", "validate"),
    ],
)
def test_invalid_operations_after_closure(first, second):
    _, manager = make_manager()
    tx = manager.begin("A")
    if first == "commit":
        manager.validate(tx)
        manager.commit(tx)
    else:
        manager.rollback(tx)
    with pytest.raises(TransactionError, match="closed"):
        if second == "mutate":
            manager.mutate(tx, "A", lambda state: state.scratchpad.append("late"))
        else:
            getattr(manager, second)(tx)


def test_events_capture_concurrency_context():
    shared = SharedState({"role": "user"})
    _, manager = make_manager(shared=shared)
    tx = manager.begin("A")
    manager.read_shared(tx, "role")
    manager.write_shared(tx, "role", "admin")
    manager.validate(tx)
    manager.commit(tx)
    assert [(event.event_type, event.session_id) for event in manager.event_log.events] == [
        ("transaction_begin", "A"),
        ("shared_state_read", "A"),
        ("shared_state_tentative_write", "A"),
        ("validation", "A"),
        ("commit", "A"),
    ]
    assert manager.read_set(tx) == {"role": 0}
    assert manager.write_set(tx) == {"role": "admin"}
