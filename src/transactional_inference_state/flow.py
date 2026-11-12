"""Deterministic cross-principal information-flow policy primitives."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .provenance import ProvenanceRegistry, RuntimeSourceType, TrustLabel


@dataclass(frozen=True)
class SecurityPrincipal:
    user_id: str
    session_id: str

    def __post_init__(self) -> None:
        if not self.user_id or not self.session_id:
            raise ValueError("principal identity must be non-empty")


@dataclass(frozen=True)
class FlowResourceScope:
    resource: str
    destination_scope: str


class FlowOutcome(str, Enum):
    FLOW_ALLOWED = "FLOW_ALLOWED"
    FLOW_DENIED = "FLOW_DENIED"
    FLOW_DECLASSIFIED = "FLOW_DECLASSIFIED"
    FLOW_DENIED_MISSING_PROVENANCE = "FLOW_DENIED_MISSING_PROVENANCE"
    FLOW_DENIED_CROSS_SESSION = "FLOW_DENIED_CROSS_SESSION"
    FLOW_DENIED_CROSS_USER = "FLOW_DENIED_CROSS_USER"
    FLOW_DENIED_CAPABILITY_SCOPE = "FLOW_DENIED_CAPABILITY_SCOPE"
    FLOW_PUBLIC_FIELD_ALLOWED = "FLOW_PUBLIC_FIELD_ALLOWED"
    FLOW_PRIVATE_FIELD_FILTERED = "FLOW_PRIVATE_FIELD_FILTERED"


@dataclass(frozen=True)
class FlowCapability:
    name: str
    user_id: str
    session_id: str
    destination_scopes: frozenset[str]


@dataclass(frozen=True)
class DeclassificationRule:
    rule_id: str
    source_session: str
    destination_scope: str
    source_id: str
    reason: str
    issuer: str
    order: int
    created_by_runtime: bool = True


@dataclass(frozen=True)
class FlowDecision:
    allowed: bool
    outcome: FlowOutcome
    reasons: tuple[str, ...]
    source_ids: tuple[str, ...]
    origin_users: tuple[str, ...]
    origin_sessions: tuple[str, ...]


@dataclass(frozen=True)
class FilteredFlowResult:
    value: dict[str, Any]
    decisions: dict[str, FlowDecision]
    fields_requested: int
    fields_allowed: int
    fields_filtered: int
    restricted_fields_leaked: int


class DeclassificationRegistry:
    """Runtime-owned explicit authorization that never rewrites provenance."""

    def __init__(self, provenance: ProvenanceRegistry, event_log: Any) -> None:
        self.provenance = provenance
        self.event_log = event_log
        self._rules: dict[str, DeclassificationRule] = {}
        self._next = 1

    def issue(self, *, source_id: str, source_session: str,
              destination_scope: str, reason: str, issuer: str,
              transaction_id: str = "runtime") -> DeclassificationRule:
        if not all((source_session, destination_scope, reason, issuer)):
            raise ValueError("declassification fields must be non-empty")
        record = self.provenance.get(source_id)
        if not record.created_by_runtime or not record.committed:
            raise ValueError("declassification requires committed runtime provenance")
        if record.origin_session != source_session:
            raise ValueError("declassification source session does not match provenance")
        rule = DeclassificationRule(
            f"declass-{self._next:06d}", source_session, destination_scope,
            source_id, reason, issuer, self._next, True,
        )
        self._next += 1
        self._rules[rule.rule_id] = rule
        self.event_log.record(
            "DECLASSIFICATION_ISSUED", transaction_id,
            session_id=source_session, rule_id=rule.rule_id,
            source_id=source_id, destination_scope=destination_scope,
            reason=reason, issuer=issuer,
        )
        return rule

    def authorizes(self, source_ids: tuple[str, ...], destination_scope: str) -> bool:
        return bool(source_ids) and all(any(
            rule.source_id == source_id
            and rule.destination_scope == destination_scope
            and rule.created_by_runtime
            for rule in self._rules.values()
        ) for source_id in source_ids)

    @property
    def rules(self) -> tuple[DeclassificationRule, ...]:
        return tuple(self._rules.values())



class FlowPolicy:
    """Default-deny cross-session policy over authoritative root lineage."""

    def __init__(self, provenance: ProvenanceRegistry,
                 declassifications: DeclassificationRegistry,
                 *, require_capability: bool = False) -> None:
        self.provenance = provenance
        self.declassifications = declassifications
        self.require_capability = require_capability

    def evaluate(self, *, current: SecurityPrincipal,
                 scope: FlowResourceScope, source_ids: tuple[str, ...],
                 capability: FlowCapability | None = None) -> FlowDecision:
        if self.require_capability and not self._capability_allows(
            current, scope, capability
        ):
            return self._decision(False, FlowOutcome.FLOW_DENIED_CAPABILITY_SCOPE,
                                  ("CAPABILITY_SCOPE",), source_ids)
        if not source_ids:
            return self._decision(False, FlowOutcome.FLOW_DENIED_MISSING_PROVENANCE,
                                  ("MISSING_AUTHORITATIVE_PROVENANCE",), source_ids)
        direct = tuple(self.provenance.get(source_id) for source_id in source_ids)
        roots = self.provenance.root_sources(source_ids)
        if self.declassifications.authorizes(source_ids, scope.destination_scope):
            return self._decision(True, FlowOutcome.FLOW_DECLASSIFIED,
                                  ("EXPLICIT_DECLASSIFICATION",), source_ids)
        if roots and all(
            record.source_type is RuntimeSourceType.SYSTEM_CONTEXT
            and record.trust_label is TrustLabel.TRUSTED
            and record.user_id == "system"
            for record in roots
        ):
            return self._decision(True, FlowOutcome.FLOW_PUBLIC_FIELD_ALLOWED,
                                  ("TRUSTED_PUBLIC_SYSTEM_SOURCE",), source_ids)
        users = {record.user_id for record in roots}
        sessions = {record.origin_session for record in roots}
        if users == {current.user_id} and sessions == {current.session_id}:
            return self._decision(True, FlowOutcome.FLOW_ALLOWED,
                                  ("SAME_PRINCIPAL",), source_ids)
        if any(user != current.user_id for user in users):
            return self._decision(False, FlowOutcome.FLOW_DENIED_CROSS_USER,
                                  ("CROSS_USER_ORIGIN",), source_ids)
        if any(session != current.session_id for session in sessions):
            return self._decision(False, FlowOutcome.FLOW_DENIED_CROSS_SESSION,
                                  ("CROSS_SESSION_ORIGIN",), source_ids)
        return self._decision(False, FlowOutcome.FLOW_DENIED,
                              ("FLOW_NOT_AUTHORIZED",), source_ids)

    def filter_fields(self, *, value: dict[str, Any],
                      field_provenance: dict[str, tuple[str, ...]],
                      requested_fields: tuple[str, ...],
                      current: SecurityPrincipal, scope: FlowResourceScope,
                      capability: FlowCapability | None = None) -> FilteredFlowResult:
        allowed: dict[str, Any] = {}
        decisions: dict[str, FlowDecision] = {}
        for field in requested_fields:
            if field not in value:
                continue
            decision = self.evaluate(
                current=current,
                scope=FlowResourceScope(scope.resource,
                                        f"{scope.destination_scope}.{field}"),
                source_ids=field_provenance.get(field, ()), capability=capability,
            )
            decisions[field] = decision
            if decision.allowed:
                allowed[field] = value[field]
        filtered = len(decisions) - len(allowed)
        return FilteredFlowResult(
            allowed, decisions, len(decisions), len(allowed), filtered, 0
        )

    def _decision(self, allowed: bool, outcome: FlowOutcome,
                  reasons: tuple[str, ...], source_ids: tuple[str, ...]) -> FlowDecision:
        return FlowDecision(
            allowed, outcome, reasons, source_ids,
            self.provenance.origin_users(source_ids),
            self.provenance.origin_sessions(source_ids),
        )

    @staticmethod
    def _capability_allows(current: SecurityPrincipal, scope: FlowResourceScope,
                           capability: FlowCapability | None) -> bool:
        return bool(
            capability and capability.name == "shared.read"
            and capability.user_id == current.user_id
            and capability.session_id == current.session_id
            and scope.destination_scope in capability.destination_scopes
        )
