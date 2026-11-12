"""Transactional staging for deterministic simulated external effects."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .runtime import EventLog, TransactionError, TransactionStatus


class EffectStatus(str, Enum):
    REQUESTED = "requested"
    STAGED = "staged"
    EXECUTED = "executed"
    DISCARDED = "discarded"
    FAILED = "failed"
    QUARANTINED = "quarantined"


class EffectClass(str, Enum):
    REVERSIBLE = "reversible"
    COMPENSATABLE = "compensatable"
    IRREVERSIBLE = "irreversible"


@dataclass
class PendingEffect:
    """Deferred action request owned by one transaction and session."""
    effect_id: str
    transaction_id: str
    session_id: str
    effect_type: str
    operation: str
    arguments: dict[str, Any]
    sequence_number: int
    idempotency_key: str | None = None
    status: EffectStatus = EffectStatus.REQUESTED
    error: str | None = None
    provenance_ids: tuple[str, ...] = ()
    dependency_ids: tuple[str, ...] = ()
    effect_class: EffectClass = EffectClass.IRREVERSIBLE


@dataclass(frozen=True)
class SentEmail:
    sequence_number: int
    to: str
    subject: str
    body: str


class SimulatedServiceError(RuntimeError):
    """Deterministic simulated target failure; no real service is contacted."""


class PartialEffectCommitError(TransactionError):
    """Signals that internal commit occurred and only a prefix of effects ran."""
    def __init__(self, transaction_id: str, failed_effect_id: str) -> None:
        super().__init__(
            f"partial external commit for {transaction_id}; "
            f"effect {failed_effect_id} failed"
        )
        self.transaction_id = transaction_id
        self.failed_effect_id = failed_effect_id


class FakeEmailService:
    """In-memory email target with deterministic failure injection."""

    def __init__(self, *, fail_on_calls: set[int] | None = None) -> None:
        self.sent_messages: list[SentEmail] = []
        self._calls = 0
        self._fail_on_calls = set(fail_on_calls or set())

    def send_email(self, *, to: str, subject: str, body: str) -> None:
        self._calls += 1
        if self._calls in self._fail_on_calls:
            raise SimulatedServiceError(
                f"injected email failure on call {self._calls}"
            )
        self.sent_messages.append(SentEmail(self._calls, to, subject, body))


class EffectManager:
    """Owns staged effects and executes them only during transaction commit.

    Ownership checks prevent one session from listing, discarding, or executing
    another transaction's effects. Execution stops at the first target failure;
    already executed effects are never represented as rolled back.
    """

    def __init__(self, email_service: FakeEmailService,
                 event_log: EventLog | None = None) -> None:
        self.email_service = email_service
        self.event_log = event_log
        self._transaction_manager: Any | None = None
        self._effects: dict[str, PendingEffect] = {}
        self._next_effect = 1
        self._next_sequence = 1
        self._executed_idempotency_keys: set[str] = set()

    def bind(self, transaction_manager: Any) -> None:
        if self._transaction_manager not in (None, transaction_manager):
            raise TransactionError("effect manager is already bound")
        self._transaction_manager = transaction_manager
        if self.event_log is None:
            self.event_log = transaction_manager.event_log

    def stage(self, transaction_id: str, session_id: str, *,
              effect_type: str, operation: str,
              arguments: dict[str, Any],
              idempotency_key: str | None = None,
              provenance_ids: tuple[str, ...] = (),
              dependency_ids: tuple[str, ...] = (),
              effect_class: EffectClass = EffectClass.IRREVERSIBLE) -> PendingEffect:
        self._require_bound()
        if self._transaction_manager.status(transaction_id) is not TransactionStatus.ACTIVE:
            raise TransactionError("effects may only be staged for an active transaction")
        # The manager's owner-checked state accessor prevents cross-session staging.
        self._transaction_manager.transaction_state(transaction_id, session_id)
        if idempotency_key is not None and not idempotency_key:
            raise ValueError("idempotency_key must be non-empty when provided")
        self._transaction_manager.validate_provenance_ids(
            transaction_id, provenance_ids
        )
        self._transaction_manager.validate_provenance_ids(
            transaction_id, dependency_ids
        )
        effect = PendingEffect(
            effect_id=f"effect-{self._next_effect:06d}",
            transaction_id=transaction_id,
            session_id=session_id,
            effect_type=effect_type,
            operation=operation,
            arguments=deepcopy(arguments),
            sequence_number=self._next_sequence,
            idempotency_key=idempotency_key,
            provenance_ids=tuple(provenance_ids),
            dependency_ids=tuple(dependency_ids), effect_class=effect_class,
        )
        self._next_effect += 1
        self._next_sequence += 1
        self._effects[effect.effect_id] = effect
        self.event_log.record("EFFECT_REQUESTED", transaction_id,
                              session_id=session_id, effect_id=effect.effect_id)
        effect.status = EffectStatus.STAGED
        self.event_log.record("EFFECT_STAGED", transaction_id,
                              session_id=session_id, effect_id=effect.effect_id,
                              sequence_number=effect.sequence_number,
                              provenance_ids=effect.provenance_ids,
                              dependency_ids=effect.dependency_ids,
                              effect_class=effect.effect_class.value)
        return deepcopy(effect)

    def list_effects(self, transaction_id: str,
                     session_id: str) -> tuple[PendingEffect, ...]:
        effects = self._owned_effects(transaction_id, session_id)
        return tuple(deepcopy(effect) for effect in effects)

    def execute_transaction(self, transaction_id: str, session_id: str) -> None:
        self._require_bound()
        if self._transaction_manager.status(transaction_id) is not TransactionStatus.COMMITTED:
            raise TransactionError("effects cannot execute before transaction commit")
        for effect in self._owned_effects(transaction_id, session_id):
            if effect.status is EffectStatus.EXECUTED:
                raise TransactionError(f"effect already executed: {effect.effect_id}")
            if effect.status is not EffectStatus.STAGED:
                raise TransactionError(
                    f"effect cannot execute in {effect.status.value} state"
                )
            if (effect.idempotency_key is not None
                    and effect.idempotency_key in self._executed_idempotency_keys):
                effect.status = EffectStatus.EXECUTED
                self.event_log.record(
                    "EFFECT_DUPLICATE_SUPPRESSED", transaction_id,
                    session_id=session_id, effect_id=effect.effect_id,
                    idempotency_key=effect.idempotency_key,
                )
                continue
            try:
                self._trigger_failure("DURING_EFFECT_EXECUTION")
                self._execute(effect)
            except Exception as error:
                effect.status = EffectStatus.FAILED
                effect.error = str(error)
                self.event_log.record(
                    "EFFECT_FAILED", transaction_id, session_id=session_id,
                    effect_id=effect.effect_id, error=str(error),
                )
                raise PartialEffectCommitError(transaction_id, effect.effect_id) from error
            effect.status = EffectStatus.EXECUTED
            if effect.idempotency_key is not None:
                self._executed_idempotency_keys.add(effect.idempotency_key)
            self.event_log.record(
                "EFFECT_EXECUTED", transaction_id, session_id=session_id,
                effect_id=effect.effect_id,
                sequence_number=effect.sequence_number,
            )
            self._trigger_failure("AFTER_FIRST_EFFECT")

    def discard_transaction(self, transaction_id: str, session_id: str) -> None:
        for effect in self._owned_effects(transaction_id, session_id):
            if effect.status is EffectStatus.EXECUTED:
                raise TransactionError("an executed effect cannot be discarded")
            if effect.status is EffectStatus.FAILED:
                raise TransactionError("a failed effect cannot be treated as discarded")
            if effect.status is EffectStatus.STAGED:
                effect.status = EffectStatus.DISCARDED
                discarded_source_ids = effect.provenance_ids
                effect.provenance_ids = ()
                self.event_log.record(
                    "EFFECT_DISCARDED", transaction_id, session_id=session_id,
                    effect_id=effect.effect_id,
                    discarded_source_ids=discarded_source_ids,
                )

    def resolve_selectively(
        self, transaction_id: str, session_id: str,
        actions: dict[str, str], blocked_dependency_ids: set[str],
    ) -> tuple[str, ...]:
        """Execute only approved effects whose explicit dependencies are safe."""
        executed: list[str] = []
        for effect in self._owned_effects(transaction_id, session_id):
            action = actions.get(effect.effect_id, "rollback")
            if blocked_dependency_ids.intersection(effect.dependency_ids):
                action = "rollback"
            if action == "commit":
                self._execute(effect)
                effect.status = EffectStatus.EXECUTED
                executed.append(effect.effect_id)
                self.event_log.record("EFFECT_EXECUTED", transaction_id,
                                      session_id=session_id, effect_id=effect.effect_id)
            elif action == "quarantine":
                effect.status = EffectStatus.QUARANTINED
                self.event_log.record("EFFECT_QUARANTINED", transaction_id,
                                      session_id=session_id, effect_id=effect.effect_id)
            else:
                effect.status = EffectStatus.DISCARDED
                self.event_log.record("EFFECT_DISCARDED", transaction_id,
                                      session_id=session_id, effect_id=effect.effect_id)
        return tuple(executed)

    def _owned_effects(self, transaction_id: str,
                       session_id: str) -> list[PendingEffect]:
        effects = [effect for effect in self._effects.values()
                   if effect.transaction_id == transaction_id]
        if effects and any(effect.session_id != session_id for effect in effects):
            raise TransactionError("effects do not belong to this session")
        # Also rejects using another session when no effects have yet been staged.
        self._transaction_manager.transaction_state(transaction_id, session_id) \
            if self._transaction_manager.status(transaction_id) in {
                TransactionStatus.ACTIVE, TransactionStatus.VALIDATED,
                TransactionStatus.REJECTED,
            } else None
        return sorted(effects, key=lambda effect: effect.sequence_number)

    def _execute(self, effect: PendingEffect) -> None:
        if effect.effect_type == "email" and effect.operation == "send":
            self.email_service.send_email(**effect.arguments)
            return
        raise SimulatedServiceError(
            f"unsupported effect: {effect.effect_type}.{effect.operation}"
        )

    def _require_bound(self) -> None:
        if self._transaction_manager is None:
            raise TransactionError("effect manager is not bound to a transaction manager")

    def _trigger_failure(self, point_name: str) -> None:
        injector = self._transaction_manager.failure_injector
        if injector is None:
            return
        from .failure import FailurePoint
        injector.trigger(FailurePoint(point_name))


class TransactionalTools:
    """Capability-limited proxy that can stage but cannot directly execute tools."""

    def __init__(self, effects: EffectManager,
                 transaction_id: str, session_id: str) -> None:
        self._effects = effects
        self._transaction_id = transaction_id
        self._session_id = session_id

    def send_email(self, *, to: str, subject: str, body: str,
                   idempotency_key: str | None = None,
                   provenance_ids: tuple[str, ...] = (),
                   dependency_ids: tuple[str, ...] = (),
                   effect_class: EffectClass = EffectClass.IRREVERSIBLE) -> PendingEffect:
        return self._effects.stage(
            self._transaction_id, self._session_id,
            effect_type="email", operation="send",
            arguments={"to": to, "subject": subject, "body": body},
            idempotency_key=idempotency_key,
            provenance_ids=provenance_ids,
            dependency_ids=dependency_ids, effect_class=effect_class,
        )
