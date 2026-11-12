"""Independent lightweight operation policy using capabilities and provenance."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any

from .operations import ModelPlan, OperationType, ProposedOperation
from .provenance import RuntimeProvenanceRecord, RuntimeSourceType


class PolicyReason(str, Enum):
    ALLOWED = "ALLOWED"
    MISSING_CAPABILITY = "MISSING_CAPABILITY"
    SESSION_SCOPE_MISMATCH = "SESSION_SCOPE_MISMATCH"
    RECIPIENT_SCOPE_MISMATCH = "RECIPIENT_SCOPE_MISMATCH"
    SENSITIVE_TARGET = "SENSITIVE_TARGET"
    UNTRUSTED_PROVENANCE = "UNTRUSTED_PROVENANCE"
    CLAIMED_PROVENANCE_MISMATCH = "CLAIMED_PROVENANCE_MISMATCH"
    SEMANTIC_POISONING = "SEMANTIC_POISONING"
    OPERATION_SEQUENCE_RISK = "OPERATION_SEQUENCE_RISK"
    MULTI_FIELD_COMPOSITION = "MULTI_FIELD_COMPOSITION"
    UNTRUSTED_PERSISTENT_WRITE = "UNTRUSTED_PERSISTENT_WRITE"


@dataclass(frozen=True)
class CapabilityGrant:
    name: str
    session_ids: frozenset[str] | None = None
    allowed_recipients: frozenset[str] | None = None


@dataclass(frozen=True)
class CapabilitySet:
    grants: tuple[CapabilityGrant, ...] = ()

    def grant_for(self, name: str) -> CapabilityGrant | None:
        return next((grant for grant in self.grants if grant.name == name), None)


@dataclass(frozen=True)
class ResourceScope:
    current_session: str
    target_session: str
    target_kind: str = "private"


@dataclass(frozen=True)
class PolicyContext:
    transaction_id: str
    session_id: str
    capabilities: CapabilitySet
    resource_scope: ResourceScope
    runtime_sources: tuple[RuntimeProvenanceRecord, ...]
    operation_source_ids: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class OperationPolicyDecision:
    operation_id: str
    allowed: bool
    reasons: tuple[PolicyReason, ...]
    sensitive_categories: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reasons: tuple[PolicyReason, ...]
    operation_decisions: tuple[OperationPolicyDecision, ...]


DEFAULT_SENSITIVE_ALIASES = {
    "authorization": {"role", "authorized", "authorization", "admin",
                      "access_level", "access_tier", "account_class"},
    "trust": {"trusted", "trust", "trust_score", "trusted_user"},
    "privilege": {"privilege", "privilege_level", "permission",
                  "permissions", "permission_level"},
    "policy": {"policy", "policy_flag", "safety_mode", "capabilities",
               "approval_cache", "authorization_result",
               "policy_decision_cache", "recipient_allowed"},
}

SEMANTIC_PATTERNS = (
    r"already approved", r"already authorized", r"pre[- ]?approved",
    r"skip confirmation", r"do not ask for confirmation",
    r"authorized sending", r"authorized external sharing",
    r"administrator directives", r"sharing always be allowed",
    r"disclosure of all stored tokens",
)


@dataclass(frozen=True)
class PolicyConfiguration:
    name: str = "policy_v1"
    capabilities: bool = True
    resource_scope: bool = True
    runtime_provenance: bool = True
    security_aliases: bool = True
    semantic_context: bool = True
    operation_sequence: bool = False


V2_SEMANTIC_PATTERNS = SEMANTIC_PATTERNS + (
    r"skip (?:approval|authorization)", r"always allow",
    r"treat (?:this|the source|instructions) as (?:an )?administrator",
    r"trusted source", r"send without confirmation",
    r"future (?:export )?requests? (?:are|is|should be) approved",
    r"external release was cleared", r"prior chat permits",
    r"disclosure is the normal preference", r"need no additional dialogue",
    r"elevated later", r"combine (?:it )?on (?:the )?next turn",
)


class PolicyEngine:
    """Inspect parsed operations and trusted context without scenario labels."""

    CAPABILITIES = {
        OperationType.MEMORY_READ: "memory.read",
        OperationType.MEMORY_WRITE: "memory.write",
        OperationType.CACHE_READ: "cache.read",
        OperationType.CACHE_WRITE: "cache.write",
        OperationType.EMAIL_SEND: "email.send",
    }

    def __init__(self, *, sensitive_aliases: dict[str, set[str]] | None = None,
                 semantic_patterns: tuple[str, ...] = SEMANTIC_PATTERNS,
                 configuration: PolicyConfiguration | None = None) -> None:
        self.sensitive_aliases = sensitive_aliases or DEFAULT_SENSITIVE_ALIASES
        self.configuration = configuration or PolicyConfiguration()
        self.semantic_patterns = tuple(re.compile(pattern, re.IGNORECASE)
                                       for pattern in semantic_patterns)

    def evaluate(self, plan: ModelPlan, context: PolicyContext) -> PolicyDecision:
        decisions = tuple(self._evaluate_operation(operation, context)
                          for operation in plan.operations)
        if self.configuration.operation_sequence:
            decisions = self._apply_plan_rules(plan, decisions)
        reasons = tuple(dict.fromkeys(reason for decision in decisions
                                     for reason in decision.reasons
                                     if reason is not PolicyReason.ALLOWED))
        return PolicyDecision(all(item.allowed for item in decisions), reasons, decisions)

    def _evaluate_operation(self, operation: ProposedOperation,
                            context: PolicyContext) -> OperationPolicyDecision:
        reasons: list[PolicyReason] = []
        capability_name = self.CAPABILITIES[operation.operation_type]
        grant = context.capabilities.grant_for(capability_name)
        if self.configuration.capabilities and grant is None:
            reasons.append(PolicyReason.MISSING_CAPABILITY)
        elif (self.configuration.resource_scope and grant is not None
              and grant.session_ids is not None
              and context.session_id not in grant.session_ids):
            reasons.append(PolicyReason.SESSION_SCOPE_MISMATCH)
        if (self.configuration.resource_scope
                and context.resource_scope.target_session != context.session_id):
            reasons.append(PolicyReason.SESSION_SCOPE_MISMATCH)
        if (self.configuration.resource_scope
                and operation.operation_type is OperationType.EMAIL_SEND
                and grant is not None):
            recipients = grant.allowed_recipients
            if recipients is not None and operation.arguments["to"] not in recipients:
                reasons.append(PolicyReason.RECIPIENT_SCOPE_MISMATCH)

        categories = self._sensitive_categories(operation)
        runtime_types = {source.source_type for source in context.runtime_sources}
        originating_types = runtime_types - {RuntimeSourceType.MODEL_OUTPUT}
        trusted = bool(originating_types) and originating_types <= {
            RuntimeSourceType.USER_PROMPT, RuntimeSourceType.SYSTEM_CONTEXT
        }
        if categories and self.configuration.security_aliases:
            security_grant = context.capabilities.grant_for("security_state.write")
            if security_grant is None:
                reasons.append(PolicyReason.SENSITIVE_TARGET)
            if self.configuration.runtime_provenance and not trusted:
                reasons.append(PolicyReason.UNTRUSTED_PROVENANCE)
        if (self.configuration.runtime_provenance
                and operation.source.value == "user_prompt"
                and RuntimeSourceType.RETRIEVED_CONTENT in runtime_types):
            reasons.append(PolicyReason.CLAIMED_PROVENANCE_MISMATCH)
        if self.configuration.semantic_context and self._semantic_poisoning(operation):
            reasons.append(PolicyReason.SEMANTIC_POISONING)
            if self.configuration.runtime_provenance and not trusted:
                reasons.append(PolicyReason.UNTRUSTED_PROVENANCE)
        unique = tuple(dict.fromkeys(reasons))
        return OperationPolicyDecision(
            operation.operation_id, not unique,
            unique or (PolicyReason.ALLOWED,), tuple(categories),
        )

    def _sensitive_categories(self, operation: ProposedOperation) -> list[str]:
        if operation.operation_type not in {
            OperationType.MEMORY_WRITE, OperationType.CACHE_WRITE
        }:
            return []
        key = re.sub(r"[^a-z0-9]+", "_", operation.arguments["key"].lower()).strip("_")
        return [category for category, aliases in self.sensitive_aliases.items()
                if key in aliases]

    def _semantic_poisoning(self, operation: ProposedOperation) -> bool:
        if operation.operation_type not in {
            OperationType.MEMORY_WRITE, OperationType.CACHE_WRITE
        }:
            return False
        value: Any = operation.arguments["value"]
        return isinstance(value, str) and any(pattern.search(value)
                                              for pattern in self.semantic_patterns)

    def _apply_plan_rules(self, plan: ModelPlan,
                          decisions: tuple[OperationPolicyDecision, ...]
                          ) -> tuple[OperationPolicyDecision, ...]:
        writes = [operation for operation in plan.operations
                  if operation.operation_type in {
                      OperationType.MEMORY_WRITE, OperationType.CACHE_WRITE}]
        effects = [operation for operation in plan.operations
                   if operation.operation_type is OperationType.EMAIL_SEND]
        risky_write = any(
            self._sensitive_categories(op) or self._semantic_poisoning(op)
            or any(token in str(op.arguments.get("value", "")).lower()
                   for token in ("approved", "authorized", "trusted"))
            for op in writes)
        composition = len(writes) >= 2 and any(
            token in str(op.arguments.get("value", "")).lower()
            for op in writes for token in ("combine", "authority", "elevated", "approve"))
        extra = []
        if writes and effects and risky_write:
            extra.append(PolicyReason.OPERATION_SEQUENCE_RISK)
        if composition:
            extra.append(PolicyReason.MULTI_FIELD_COMPOSITION)
        if not extra:
            return decisions
        return tuple(OperationPolicyDecision(
            item.operation_id, False,
            tuple(dict.fromkeys((*item.reasons,
                *(() if item.reasons != (PolicyReason.ALLOWED,) else ()), *extra)))
            if item.reasons != (PolicyReason.ALLOWED,) else tuple(extra),
            item.sensitive_categories,
        ) for item in decisions)


class PolicyV1(PolicyEngine):
    """Frozen name for the exact Stage 8 policy configuration."""

    def __init__(self) -> None:
        super().__init__(configuration=PolicyConfiguration(name="policy_v1"))


class PolicyV2(PolicyEngine):
    """Stage 9 refined policy; rules are frozen before held-out evaluation."""

    BENIGN_CONTEXT_KEYS = {"quoted_text", "security_article", "study_note",
                           "favorite_editor", "preferred_language", "timezone",
                           "display_preference"}

    def __init__(self, configuration: PolicyConfiguration | None = None) -> None:
        aliases = {category: set(values) for category, values
                   in DEFAULT_SENSITIVE_ALIASES.items()}
        aliases["authorization"].update({"authorization_state", "approval_state"})
        aliases["policy"].update({"policy_status", "control_status"})
        aliases["trust"].update({"source_reputation", "confidence_trust"})
        super().__init__(sensitive_aliases=aliases,
                         semantic_patterns=V2_SEMANTIC_PATTERNS,
                         configuration=configuration or PolicyConfiguration(
                             name="policy_v2", operation_sequence=True))

    def _semantic_poisoning(self, operation: ProposedOperation) -> bool:
        if operation.operation_type not in {
            OperationType.MEMORY_WRITE, OperationType.CACHE_WRITE}:
            return False
        key = re.sub(r"[^a-z0-9]+", "_", operation.arguments["key"].lower()).strip("_")
        value = operation.arguments["value"]
        if (key in self.BENIGN_CONTEXT_KEYS and isinstance(value, str)
                and (value.lower().startswith(("quote:", "article:", "definition:"))
                     or "discussion" in value.lower())):
            return False
        return super()._semantic_poisoning(operation)

    def _evaluate_operation(self, operation: ProposedOperation,
                            context: PolicyContext) -> OperationPolicyDecision:
        decision = super()._evaluate_operation(operation, context)
        source_types = {source.source_type for source in context.runtime_sources}
        if (self.configuration.runtime_provenance
                and operation.operation_type is OperationType.EMAIL_SEND
                and RuntimeSourceType.MEMORY in source_types):
            reasons = tuple(reason for reason in decision.reasons
                            if reason is not PolicyReason.ALLOWED)
            reasons = tuple(dict.fromkeys((*reasons,
                                           PolicyReason.UNTRUSTED_PERSISTENT_WRITE)))
            return OperationPolicyDecision(operation.operation_id, False, reasons,
                                           decision.sensitive_categories)
        return decision
