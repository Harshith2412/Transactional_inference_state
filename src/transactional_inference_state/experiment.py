"""Deterministic Stage 1 attack experiment."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from .runtime import (
    Event,
    InferenceState,
    PolicyValidator,
    SessionManager,
    SharedState,
    TransactionManager,
    TransactionStatus,
    WriteConflictError,
)


@dataclass(frozen=True)
class AttackExperimentResult:
    initial_state: InferenceState
    final_state: InferenceState
    rejected: bool
    restored_exactly: bool
    events: tuple[Event, ...]


def run_attack_experiment() -> AttackExperimentResult:
    """Attempt an unsafe memory write, reject it, and prove exact restoration."""

    state = InferenceState(
        session_memory={"trusted_fact": "known-safe-value"},
        scratchpad=["baseline reasoning"],
        application_cache={"model_config": "stage-1"},
        retrieved_data=[{"source": "fixture", "value": 7}],
        tool_results=[{"tool": "deterministic", "result": "ok"}],
        pending_memory_writes=[],
        user_session_metadata={"session_id": "attack-experiment"},
        security_state={"trusted": True, "violations": 0},
    )
    initial_state = deepcopy(state)
    manager = TransactionManager(state, validator=PolicyValidator(accept=False))

    manager.begin()
    state.session_memory["trusted_fact"] = "ATTACKER-CONTROLLED"
    state.pending_memory_writes.append({"persist": "malicious instruction"})
    state.security_state["violations"] = 1
    manager.record_mutation(
        "unsafe memory mutation", fields=[
            "session_memory", "pending_memory_writes", "security_state"
        ]
    )
    accepted = manager.validate()
    manager.rollback()

    return AttackExperimentResult(
        initial_state=initial_state,
        final_state=deepcopy(state),
        rejected=not accepted,
        restored_exactly=state == initial_state,
        events=manager.event_log.events,
    )


@dataclass(frozen=True)
class DirtyReadExperimentResult:
    committed_before: str
    transaction_a_tentative: str
    transaction_b_observed: str
    dirty_read_prevented: bool


def run_dirty_read_experiment() -> DirtyReadExperimentResult:
    sessions = SessionManager()
    sessions.create_session("A")
    sessions.create_session("B")
    shared = SharedState({"role": "user"})
    manager = TransactionManager(sessions, shared_state=shared)
    transaction_a = manager.begin("A")
    transaction_b = manager.begin("B")
    manager.write_shared(transaction_a, "role", "admin")
    observed = manager.read_shared(transaction_b, "role")
    return DirtyReadExperimentResult("user", "admin", observed, observed == "user")


@dataclass(frozen=True)
class WriteConflictExperimentResult:
    initial_version: int
    committed_value: str
    committed_version: int
    second_status: TransactionStatus
    conflict_detected: bool


def run_write_conflict_experiment() -> WriteConflictExperimentResult:
    sessions = SessionManager()
    sessions.create_session("A")
    sessions.create_session("B")
    shared = SharedState({"role": "user"})
    manager = TransactionManager(sessions, shared_state=shared)
    transaction_a = manager.begin("A")
    transaction_b = manager.begin("B")
    manager.read_shared(transaction_a, "role")
    manager.read_shared(transaction_b, "role")
    manager.write_shared(transaction_a, "role", "admin")
    manager.write_shared(transaction_b, "role", "auditor")
    manager.validate(transaction_a)
    manager.validate(transaction_b)
    manager.commit(transaction_a)
    try:
        manager.commit(transaction_b)
        conflict = False
    except WriteConflictError:
        conflict = True
    committed = shared.read("role")
    return WriteConflictExperimentResult(
        initial_version=0,
        committed_value=committed.value,
        committed_version=committed.version,
        second_status=manager.status(transaction_b),
        conflict_detected=conflict,
    )
