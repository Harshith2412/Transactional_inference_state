from copy import deepcopy

import pytest

from transactional_inference_state import (
    DeltaStrategy,
    FullCopyStrategy,
    InferenceState,
    PolicyValidator,
    SessionManager,
    TransactionManager,
    canonical_state_bytes,
    generate_benchmark_state,
    run_benchmark,
    state_digest,
)


def manager_for(strategy, initial, accepted=True):
    sessions = SessionManager()
    state = sessions.create_session("session")
    for name, value in vars(deepcopy(initial)).items():
        setattr(state, name, value)
    manager = TransactionManager(
        sessions, snapshot_strategy=strategy,
        validator=PolicyValidator(accepted),
    )
    return state, manager


@pytest.mark.parametrize("strategy", [FullCopyStrategy(), DeltaStrategy()])
def test_strategy_commit_and_rollback(strategy):
    initial = InferenceState(session_memory={"one": 1})
    state, manager = manager_for(strategy, initial)
    tx = manager.begin("session")
    manager.write_private(tx, "session", "session_memory", "one", 2)
    manager.validate(tx)
    manager.commit(tx)
    assert state.session_memory == {"one": 2}

    rejected_state, rejected = manager_for(strategy, initial, accepted=False)
    tx = rejected.begin("session")
    rejected.write_private(tx, "session", "session_memory", "one", 3)
    rejected.validate(tx)
    rejected.rollback(tx)
    assert rejected_state == initial


@pytest.mark.parametrize("strategy", [FullCopyStrategy(), DeltaStrategy()])
@pytest.mark.parametrize("nested", [
    {"permissions": ["read"]},
    {"groups": [{"permissions": ["read"]}]},
    [[{"permissions": ["read"]}]],
])
def test_nested_mutable_read_modify_write_is_alias_safe(strategy, nested):
    initial = InferenceState(session_memory={"profile": nested})
    state, manager = manager_for(strategy, initial, accepted=False)
    tx = manager.begin("session")
    local = manager.read_private(tx, "session", "session_memory", "profile")
    if "permissions" in local if isinstance(local, dict) else False:
        local["permissions"].append("admin")
    elif isinstance(local, dict):
        local["groups"][0]["permissions"].append("admin")
    else:
        local[0][0]["permissions"].append("admin")
    manager.write_private(tx, "session", "session_memory", "profile", local)
    manager.validate(tx)
    manager.rollback(tx)
    assert state == initial


@pytest.mark.parametrize("strategy", [FullCopyStrategy(), DeltaStrategy()])
def test_nested_mutation_commit(strategy):
    initial = InferenceState(
        session_memory={"profile": {"permissions": ["read"]}}
    )
    state, manager = manager_for(strategy, initial)
    tx = manager.begin("session")
    profile = manager.read_private(tx, "session", "session_memory", "profile")
    profile["permissions"].append("admin")
    manager.write_private(tx, "session", "session_memory", "profile", profile)
    manager.validate(tx)
    manager.commit(tx)
    assert state.session_memory["profile"] == {"permissions": ["read", "admin"]}


@pytest.mark.parametrize("strategy", [FullCopyStrategy(), DeltaStrategy()])
@pytest.mark.parametrize("accepted", [True, False])
def test_delete_commit_and_rollback(strategy, accepted):
    initial = InferenceState(session_memory={"keep": 1, "delete": 2})
    state, manager = manager_for(strategy, initial, accepted=accepted)
    tx = manager.begin("session")
    manager.delete_private(tx, "session", "session_memory", "delete")
    manager.validate(tx)
    if accepted:
        manager.commit(tx)
        assert state.session_memory == {"keep": 1}
    else:
        manager.rollback(tx)
        assert state == initial


def test_canonical_digest_stability_and_sensitivity():
    first = InferenceState(session_memory={"b": 2, "a": {"nested": [1, 2]}})
    equal = InferenceState(session_memory={"a": {"nested": [1, 2]}, "b": 2})
    changed = deepcopy(first)
    changed.session_memory["a"]["nested"].append(3)
    assert canonical_state_bytes(first) == canonical_state_bytes(first)
    assert state_digest(first) == state_digest(equal)
    assert state_digest(first) != state_digest(changed)
    assert len(state_digest(first)) == 64


def test_workload_generation_is_deterministic_and_approximately_sized():
    first = generate_benchmark_state(10 * 1024)
    second = generate_benchmark_state(10 * 1024)
    assert first == second
    size = len(canonical_state_bytes(first))
    assert 10 * 1024 <= size < 12 * 1024


@pytest.mark.parametrize("strategy", [FullCopyStrategy(), DeltaStrategy()])
@pytest.mark.parametrize("operation", ["commit", "rollback"])
def test_benchmark_result_schema_and_correctness(strategy, operation):
    result = run_benchmark(
        strategy, target_bytes=2048, mutation_ratio=0.1,
        operation_type=operation, iterations=2,
    )
    data = result.to_dict()
    assert data["strategy"] == strategy.name
    assert data["operation_type"] == operation
    assert data["iterations"] == 2
    assert data["rollback_integrity"] is True
    assert set(data["phase_metrics"]) == {
        "begin", "mutation", "validation", operation, "total"
    }
    for required in (
        "mean_latency_ns", "median_latency_ns", "min_latency_ns",
        "max_latency_ns", "stdev_latency_ns", "mean_memory_overhead_bytes",
    ):
        assert data[required] >= 0
