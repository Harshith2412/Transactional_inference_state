"""Opt-in, validator-directed selective transaction resolution for Stage 12D."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from typing import Any, Protocol

from .cow import FieldPath, FineGrainedCOWStrategy
from .provenance import RuntimeProvenanceRecord, TrustLabel
from .runtime import TransactionError, TransactionStatus


class DecisionAction(str, Enum):
    COMMIT = "commit"
    ROLLBACK = "rollback"
    QUARANTINE = "quarantine"
    REQUIRE_REVIEW = "require_review"
    SELECTIVE_COMMIT = "selective_commit"


@dataclass(frozen=True)
class FieldDecision:
    path: FieldPath
    action: DecisionAction
    reason: str
    confidence: float | None = None
    provenance_ids: tuple[str, ...] = ()
    dependency_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class EffectDecision:
    effect_id: str
    action: DecisionAction
    reason: str
    confidence: float | None = None
    dependency_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ValidationDecision:
    action: DecisionAction
    confidence: float | None = None
    reasons: tuple[str, ...] = ()
    field_decisions: tuple[FieldDecision, ...] = ()
    effect_decisions: tuple[EffectDecision, ...] = ()
    validator_disagreement: bool = False


@dataclass(frozen=True)
class ValidationContext:
    transaction_id: str
    session_id: str
    fields: tuple[FieldDecision, ...]
    operations: tuple[str, ...] = ()


class Validator(Protocol):
    def evaluate(self, context: ValidationContext) -> ValidationDecision: ...


@dataclass(frozen=True)
class ConfidenceThresholds:
    commit_at_or_above: float = .85
    rollback_at_or_above: float = .85
    uncertain_action: DecisionAction = DecisionAction.QUARANTINE

    def __post_init__(self) -> None:
        if not 0 <= self.commit_at_or_above <= 1 or not 0 <= self.rollback_at_or_above <= 1:
            raise ValueError("confidence thresholds must be between zero and one")


class StaticRuleValidator:
    """Small deterministic rule validator, separate from frozen PolicyV1/V2."""
    POISONING = (
        "already approved", "already authorized", "do not ask for confirmation",
        "grants permission", "future data release",
    )

    def evaluate(self, context: ValidationContext) -> ValidationDecision:
        decisions = []
        for proposal in context.fields:
            text = proposal.reason.lower()
            deny = any(marker in text for marker in self.POISONING)
            decisions.append(FieldDecision(
                proposal.path,
                DecisionAction.ROLLBACK if deny else DecisionAction.COMMIT,
                "semantic memory-poisoning rule" if deny else "static rules allow",
                .98, proposal.provenance_ids, proposal.dependency_ids,
            ))
        action = DecisionAction.SELECTIVE_COMMIT if decisions else DecisionAction.COMMIT
        return ValidationDecision(action, .98, ("static rule evaluation",), tuple(decisions))


class ConfidenceValidator:
    """Maps trusted signed scores to configured deterministic actions."""
    def __init__(self, scores: dict[str, float],
                 thresholds: ConfidenceThresholds = ConfidenceThresholds()):
        if any(not -1 <= score <= 1 for score in scores.values()):
            raise ValueError("signed confidence scores must be in [-1, 1]")
        self.scores, self.thresholds = dict(scores), thresholds

    def evaluate(self, context: ValidationContext) -> ValidationDecision:
        decisions = []
        for proposal in context.fields:
            score = self.scores.get(proposal.path.canonical(), 0.0)
            if score >= self.thresholds.commit_at_or_above:
                action = DecisionAction.COMMIT
            elif score <= -self.thresholds.rollback_at_or_above:
                action = DecisionAction.ROLLBACK
            else:
                action = self.thresholds.uncertain_action
            decisions.append(FieldDecision(
                proposal.path, action, "configured confidence threshold",
                abs(score), proposal.provenance_ids, proposal.dependency_ids,
            ))
        return ValidationDecision(DecisionAction.SELECTIVE_COMMIT, None,
                                  ("confidence thresholds applied",), tuple(decisions))


class ProvenanceFlowValidator:
    def __init__(self, registry: Any, *, unsafe_action: DecisionAction = DecisionAction.QUARANTINE):
        self.registry = registry
        self.unsafe_action = unsafe_action

    def evaluate(self, context: ValidationContext) -> ValidationDecision:
        decisions = []
        for proposal in context.fields:
            lineage = self.registry.lineage(proposal.provenance_ids) if proposal.provenance_ids else ()
            unsafe = any(record.trust_label in {TrustLabel.UNTRUSTED, TrustLabel.MIXED}
                         for record in lineage)
            decisions.append(FieldDecision(
                proposal.path, self.unsafe_action if unsafe else DecisionAction.COMMIT,
                "untrusted provenance lineage" if unsafe else "trusted provenance lineage",
                .97, proposal.provenance_ids, proposal.dependency_ids,
            ))
        return ValidationDecision(DecisionAction.SELECTIVE_COMMIT, .97,
                                  ("provenance flow evaluation",), tuple(decisions))


class SequenceValidator:
    """Rejects explicitly represented approval→secret→effect sequences."""
    def evaluate(self, context: ValidationContext) -> ValidationDecision:
        dangerous = all(any(token in op.lower() for op in context.operations)
                        for token in ("approval", "secret", "email"))
        action = DecisionAction.ROLLBACK if dangerous else DecisionAction.COMMIT
        fields = tuple(FieldDecision(
            item.path, action,
            "dangerous approval-secret-email sequence" if dangerous else "sequence allowed",
            .99, item.provenance_ids, item.dependency_ids,
        ) for item in context.fields)
        return ValidationDecision(
            DecisionAction.SELECTIVE_COMMIT if fields else action, .99,
            ("sequence dependency evaluated",), fields,
        )


class CompositionRule(str, Enum):
    DENY_OVERRIDES = "deny_overrides"
    ALL_MUST_APPROVE = "all_must_approve"


class CompositeValidator:
    def __init__(self, validators: tuple[Validator, ...],
                 rule: CompositionRule = CompositionRule.DENY_OVERRIDES,
                 *, disagreement_action: DecisionAction = DecisionAction.QUARANTINE):
        if not validators:
            raise ValueError("at least one validator is required")
        self.validators, self.rule, self.disagreement_action = validators, rule, disagreement_action

    def evaluate(self, context: ValidationContext) -> ValidationDecision:
        results = tuple(validator.evaluate(context) for validator in self.validators)
        by_path: dict[FieldPath, list[FieldDecision]] = {}
        for result in results:
            for item in result.field_decisions:
                by_path.setdefault(item.path, []).append(item)
        merged = []
        disagreement = False
        for path, votes in by_path.items():
            actions = {vote.action for vote in votes}
            disagreement |= len(actions) > 1
            denies = [vote for vote in votes if vote.action in {
                DecisionAction.ROLLBACK, DecisionAction.QUARANTINE,
                DecisionAction.REQUIRE_REVIEW,
            }]
            if denies:
                chosen = denies[0]
                action = (self.disagreement_action if len(actions) > 1
                          and self.rule is CompositionRule.DENY_OVERRIDES else chosen.action)
            elif self.rule is CompositionRule.ALL_MUST_APPROVE and len(votes) != len(results):
                chosen, action = votes[0], DecisionAction.ROLLBACK
            else:
                chosen, action = votes[0], DecisionAction.COMMIT
            merged.append(FieldDecision(path, action, "; ".join(v.reason for v in votes),
                                        min(v.confidence or 1 for v in votes),
                                        chosen.provenance_ids, chosen.dependency_ids))
        return ValidationDecision(DecisionAction.SELECTIVE_COMMIT, None,
                                  tuple(r for result in results for r in result.reasons),
                                  tuple(merged), validator_disagreement=disagreement)


@dataclass(frozen=True)
class QuarantinedValue:
    quarantine_id: str
    transaction_id: str
    session_id: str
    path: FieldPath
    value: Any
    provenance: tuple[RuntimeProvenanceRecord, ...]
    lineage: tuple[RuntimeProvenanceRecord, ...]
    reasons: tuple[str, ...]
    decision: FieldDecision


class QuarantineStore:
    """Trusted, explicitly inspected storage; ordinary transaction reads never consult it."""
    def __init__(self) -> None:
        self._values: dict[str, QuarantinedValue] = {}
        self._next_id = 1

    def add(self, transaction_id: str, session_id: str, decision: FieldDecision,
            value: Any, registry: Any) -> QuarantinedValue:
        provenance = tuple(registry.get(item) for item in decision.provenance_ids)
        lineage = registry.lineage(decision.provenance_ids) if decision.provenance_ids else ()
        item = QuarantinedValue(
            f"quarantine-{self._next_id:06d}", transaction_id, session_id,
            decision.path, deepcopy(value), provenance, tuple(lineage),
            (decision.reason,), decision,
        )
        self._next_id += 1
        self._values[item.quarantine_id] = item
        return deepcopy(item)

    def get(self, quarantine_id: str) -> QuarantinedValue:
        return deepcopy(self._values[quarantine_id])

    def list_for_transaction(self, transaction_id: str) -> tuple[QuarantinedValue, ...]:
        return tuple(deepcopy(item) for item in self._values.values()
                     if item.transaction_id == transaction_id)


@dataclass(frozen=True)
class SelectiveResolution:
    transaction_id: str
    status: TransactionStatus
    committed_paths: tuple[FieldPath, ...]
    rolled_back_paths: tuple[FieldPath, ...]
    quarantined_paths: tuple[FieldPath, ...]
    blocked_dependent_paths: tuple[FieldPath, ...]
    executed_effect_ids: tuple[str, ...] = ()


class SelectiveTransactionResolver:
    """Deterministically enforces trusted decisions; it does no threat classification."""
    def __init__(self, manager: Any, quarantine: QuarantineStore | None = None) -> None:
        self.manager = manager
        self.quarantine = quarantine or QuarantineStore()
        self._reviews: dict[str, tuple[str, ValidationDecision]] = {}

    def resolve(self, transaction_id: str, decision: ValidationDecision) -> SelectiveResolution:
        tx = self.manager._get(transaction_id)
        if tx.status is not TransactionStatus.ACTIVE:
            raise TransactionError("selective resolution requires an active transaction")
        if decision.action is DecisionAction.REQUIRE_REVIEW:
            token = self._review_token(tx)
            self._reviews[transaction_id] = (token, decision)
            tx.status = TransactionStatus.REVIEW_REQUIRED
            self.manager.event_log.record("review_required", transaction_id,
                                          session_id=tx.session_id, review_token=token)
            return SelectiveResolution(transaction_id, tx.status, (), (), (), ())
        if decision.action is DecisionAction.COMMIT:
            self.manager.validate(transaction_id); self.manager.commit(transaction_id)
            return SelectiveResolution(transaction_id, tx.status, (), (), (), ())
        if decision.action is DecisionAction.ROLLBACK:
            self.manager.rollback(transaction_id)
            return SelectiveResolution(transaction_id, tx.status, (), (), (), ())
        if decision.action is DecisionAction.QUARANTINE:
            decisions = tuple(FieldDecision(
                p, DecisionAction.QUARANTINE, "transaction quarantine",
                provenance_ids=self._path_sources(tx, p),
            ) for p in tx.strategy_context.modified_paths
              if p.field_name != "provenance_metadata")
            decision = ValidationDecision(DecisionAction.SELECTIVE_COMMIT,
                                          decision.confidence, decision.reasons, decisions)
        if decision.action is not DecisionAction.SELECTIVE_COMMIT:
            raise TransactionError(f"unsupported decision: {decision.action.value}")
        return self._selective(tx, decision)

    def approve_review(self, transaction_id: str, review_token: str,
                       decision: ValidationDecision) -> SelectiveResolution:
        tx = self.manager._get(transaction_id)
        expected, _ = self._reviews.get(transaction_id, (None, None))
        if tx.status is not TransactionStatus.REVIEW_REQUIRED or review_token != expected:
            raise TransactionError("stale or invalid review resolution")
        tx.status = TransactionStatus.ACTIVE
        del self._reviews[transaction_id]
        return self.resolve(transaction_id, decision)

    def reject_review(self, transaction_id: str, review_token: str) -> SelectiveResolution:
        return self.approve_review(transaction_id, review_token,
                                   ValidationDecision(DecisionAction.ROLLBACK))

    def quarantine_review(self, transaction_id: str, review_token: str) -> SelectiveResolution:
        return self.approve_review(transaction_id, review_token,
                                   ValidationDecision(DecisionAction.QUARANTINE))

    def review_token(self, transaction_id: str) -> str:
        try:
            return self._reviews[transaction_id][0]
        except KeyError as error:
            raise TransactionError("transaction is not awaiting review") from error

    def _selective(self, tx: Any, decision: ValidationDecision) -> SelectiveResolution:
        if not isinstance(self.manager.snapshot_strategy, FineGrainedCOWStrategy):
            raise TransactionError("selective commit requires FineGrainedCOWStrategy")
        declared = {item.path: item for item in decision.field_decisions}
        changed = {path for path in tx.strategy_context.modified_paths
                   if path.field_name != "provenance_metadata"}
        if set(declared) != changed:
            raise TransactionError("field decisions must cover every modified field path exactly")
        for path, item in declared.items():
            if item.provenance_ids != self._path_sources(tx, path):
                raise TransactionError(
                    f"field decision provenance does not match authoritative path metadata: "
                    f"{path.canonical()}"
                )
        blocked_ids: set[str] = set()
        for item in declared.values():
            if item.action is not DecisionAction.COMMIT:
                blocked_ids.update(item.provenance_ids)
                blocked_ids.update(item.dependency_ids)
        contaminated: set[FieldPath] = set()
        for item in declared.values():
            lineage_ids = {record.source_id for record in
                           self.manager.provenance_registry.lineage(item.provenance_ids)} \
                          if item.provenance_ids else set()
            if item.action is DecisionAction.COMMIT and blocked_ids.intersection(
                    lineage_ids | set(item.dependency_ids)):
                contaminated.add(item.path)
        fresh = self.manager.snapshot_strategy.begin(
            self.manager.sessions.get_session(tx.session_id)
        )
        committed, rolled, quarantined = [], [], []
        committed_sources: set[str] = set()
        for path, item in declared.items():
            action = DecisionAction.QUARANTINE if path in contaminated else item.action
            value = self.manager.snapshot_strategy.read_path(tx.strategy_context, path)
            if action is DecisionAction.COMMIT:
                self.manager.snapshot_strategy.write_path(fresh, path, value)
                if item.provenance_ids:
                    self.manager.snapshot_strategy.write(
                        fresh, "provenance_metadata", path.canonical(), item.provenance_ids
                    )
                    committed_sources.update(
                        record.source_id for record in
                        self.manager.provenance_registry.lineage(item.provenance_ids)
                        if self.manager.provenance_registry.is_tentative_for(
                            record.source_id, tx.transaction_id)
                    )
                committed.append(path)
            elif action is DecisionAction.QUARANTINE:
                self.quarantine.add(tx.transaction_id, tx.session_id, item, value,
                                    self.manager.provenance_registry)
                quarantined.append(path)
            else:
                rolled.append(path)
        self.manager.snapshot_strategy.commit(fresh, self.manager.sessions.get_session(tx.session_id))
        committed_records, discarded_records = self.manager.provenance_registry.resolve_transaction(
            tx.transaction_id, tuple(sorted(committed_sources))
        )
        self.manager._record_provenance_closure(tx, committed_records, committed=True)
        self.manager._record_provenance_closure(tx, discarded_records, committed=False)
        effect_actions = {item.effect_id: item.action.value for item in decision.effect_decisions}
        executed = ()
        tx.status = TransactionStatus.PARTIALLY_COMMITTED if committed else (
            TransactionStatus.QUARANTINED if quarantined else TransactionStatus.ROLLED_BACK
        )
        if self.manager.effect_manager is not None:
            executed = self.manager.effect_manager.resolve_selectively(
                tx.transaction_id, tx.session_id, effect_actions, blocked_ids
            )
        self.manager.event_log.record(
            "selective_commit", tx.transaction_id, session_id=tx.session_id,
            committed_paths=tuple(p.canonical() for p in committed),
            rolled_back_paths=tuple(p.canonical() for p in rolled),
            quarantined_paths=tuple(p.canonical() for p in quarantined),
            blocked_dependent_paths=tuple(p.canonical() for p in contaminated),
        )
        return SelectiveResolution(tx.transaction_id, tx.status, tuple(committed),
                                   tuple(rolled), tuple(quarantined),
                                   tuple(contaminated), executed)

    @staticmethod
    def _review_token(tx: Any) -> str:
        paths = "|".join(sorted(path.canonical() for path in tx.strategy_context.modified_paths))
        return hashlib.sha256(f"{tx.transaction_id}|{tx.session_id}|{paths}".encode()).hexdigest()

    def _path_sources(self, tx: Any, path: FieldPath) -> tuple[str, ...]:
        try:
            return tuple(self.manager.snapshot_strategy.read(
                tx.strategy_context, "provenance_metadata", path.canonical()
            ))
        except KeyError:
            return ()
