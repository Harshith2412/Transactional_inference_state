"""Authoritative in-process lineage tracing and selective recovery."""
from __future__ import annotations

from collections import deque
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Any

from .cow import FieldPath
from .provenance import TrustLabel
from .runtime import EventLog, TransactionError


class LineageNodeType(str, Enum):
    USER_INPUT = "user_input"
    RETRIEVAL = "retrieval"
    TOOL_RESULT = "tool_result"
    MODEL_OUTPUT = "model_output"
    TRANSACTION = "transaction"
    SUMMARY = "summary"
    MEMORY = "memory"
    CACHE = "cache"
    SHARED_STATE = "shared_state"
    EFFECT = "effect"
    QUARANTINED_STATE = "quarantined_state"
    CONTEXT = "context"


class LineageNodeStatus(str, Enum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    INVALIDATED = "invalidated"


@dataclass(frozen=True)
class StateReference:
    session_id: str
    path: FieldPath


@dataclass
class LineageNode:
    node_id: str
    node_type: LineageNodeType
    user_id: str | None = None
    session_id: str | None = None
    transaction_id: str | None = None
    source_id: str | None = None
    trust_label: TrustLabel = TrustLabel.UNKNOWN
    state_reference: StateReference | None = None
    committed: bool = True
    verified_lineage: bool = True
    status: LineageNodeStatus = LineageNodeStatus.ACTIVE
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LineageEdge:
    parent_id: str
    child_id: str
    relationship: str = "derived_from"


@dataclass(frozen=True)
class ContaminationReport:
    suspicious_node_id: str
    direct_source_ids: tuple[str, ...]
    upstream_untrusted_ids: tuple[str, ...]
    contaminated_node_ids: tuple[str, ...]
    committed_value_ids: tuple[str, ...]
    downstream_state_ids: tuple[str, ...]
    affected_transaction_ids: tuple[str, ...]
    unrelated_committed_ids: tuple[str, ...]


class RecoveryAction(str, Enum):
    QUARANTINE = "quarantine"
    INVALIDATE = "invalidate"
    PRESERVE = "preserve"


@dataclass(frozen=True)
class RecoveryStep:
    node_id: str
    action: RecoveryAction
    reason: str


@dataclass(frozen=True)
class RecoveryPlan:
    suspicious_node_id: str
    graph_revision: int
    steps: tuple[RecoveryStep, ...]


@dataclass(frozen=True)
class RecoveryQuarantineEntry:
    node_id: str
    value: Any
    node: LineageNode
    reason: str


@dataclass(frozen=True)
class RecoveryResult:
    quarantined_ids: tuple[str, ...]
    invalidated_ids: tuple[str, ...]
    preserved_ids: tuple[str, ...]


class LineageGraph:
    """Explicit dependency DAG. No edge is inferred from content."""
    _RECOVERABLE = {
        LineageNodeType.MEMORY, LineageNodeType.SUMMARY, LineageNodeType.CACHE,
        LineageNodeType.SHARED_STATE, LineageNodeType.CONTEXT,
    }

    def __init__(self, event_log: EventLog | None = None) -> None:
        self.event_log = event_log or EventLog()
        self._nodes: dict[str, LineageNode] = {}
        self._parents: dict[str, set[str]] = {}
        self._children: dict[str, set[str]] = {}
        self._edges: dict[tuple[str, str], LineageEdge] = {}
        self._references: dict[tuple[str, str], str] = {}
        self._quarantine: dict[str, RecoveryQuarantineEntry] = {}
        self._ranks: dict[str, int] = {}
        self._revision = 0

    @property
    def revision(self) -> int: return self._revision
    @property
    def nodes(self) -> tuple[LineageNode, ...]:
        return tuple(deepcopy(self._nodes[key]) for key in sorted(self._nodes))
    @property
    def edges(self) -> tuple[LineageEdge, ...]:
        return tuple(self._edges[key] for key in sorted(self._edges))

    def add_node(self, node: LineageNode) -> LineageNode:
        if not node.node_id:
            raise ValueError("lineage node ID must not be empty")
        if node.node_id in self._nodes:
            raise ValueError(f"duplicate lineage node: {node.node_id}")
        if node.state_reference is not None:
            key = (node.state_reference.session_id,
                   node.state_reference.path.canonical())
            if key in self._references:
                raise ValueError(f"state reference already has a lineage node: {key}")
            self._references[key] = node.node_id
        self._nodes[node.node_id] = deepcopy(node)
        self._ranks[node.node_id] = len(self._ranks)
        self._parents[node.node_id] = set(); self._children[node.node_id] = set()
        self._revision += 1
        return deepcopy(node)

    def add_edge(self, parent_id: str, child_id: str,
                 relationship: str = "derived_from") -> LineageEdge:
        self.get(parent_id); self.get(child_id)
        if (parent_id == child_id or
                (self._ranks[parent_id] >= self._ranks[child_id]
                 and parent_id in self.descendant_ids(child_id))):
            raise ValueError("lineage edges must remain acyclic")
        edge = LineageEdge(parent_id, child_id, relationship)
        if (parent_id, child_id) not in self._edges:
            self._edges[(parent_id, child_id)] = edge
            self._parents[child_id].add(parent_id); self._children[parent_id].add(child_id)
            self._revision += 1
        return edge

    def get(self, node_id: str) -> LineageNode:
        try: return deepcopy(self._nodes[node_id])
        except KeyError as error: raise KeyError(f"unknown lineage node: {node_id}") from error

    def ancestor_ids(self, node_id: str) -> tuple[str, ...]:
        return self._walk(node_id, self._parents)

    def descendant_ids(self, node_id: str) -> tuple[str, ...]:
        return self._walk(node_id, self._children)

    def ancestors(self, node_id: str) -> tuple[LineageNode, ...]:
        return tuple(self.get(item) for item in self.ancestor_ids(node_id))

    def descendants(self, node_id: str) -> tuple[LineageNode, ...]:
        return tuple(self.get(item) for item in self.descendant_ids(node_id))

    def origin_users(self, node_id: str) -> tuple[str, ...]:
        return self._origins(node_id, "user_id")

    def origin_sessions(self, node_id: str) -> tuple[str, ...]:
        return self._origins(node_id, "session_id")

    def origin_transactions(self, node_id: str) -> tuple[str, ...]:
        return self._origins(node_id, "transaction_id")

    def origin_sources(self, node_id: str) -> tuple[str, ...]:
        return self._origins(node_id, "source_id")

    def first_untrusted_ancestor(self, node_id: str) -> LineageNode | None:
        risky = self.all_untrusted_ancestors(node_id)
        result = risky[0] if risky else None
        self.event_log.record("ROOT_CAUSE_QUERY", node_id,
                              root_node_id=None if result is None else result.node_id)
        return result

    def all_untrusted_ancestors(self, node_id: str) -> tuple[LineageNode, ...]:
        return tuple(node for node in self.ancestors(node_id)
                     if node.trust_label is TrustLabel.UNTRUSTED
                     or not node.verified_lineage)

    def analyze_contamination(self, suspicious_node_id: str) -> ContaminationReport:
        suspicious = self.get(suspicious_node_id)
        ancestors = set(self.ancestor_ids(suspicious_node_id))
        risky = {node.node_id for node in self.all_untrusted_ancestors(suspicious_node_id)}
        contaminated: set[str] = {suspicious_node_id}
        for root in risky:
            contaminated.add(root)
            contaminated.update(self.descendant_ids(root))
        downstream = {item for item in contaminated - ancestors - {suspicious_node_id}
                      if self._nodes[item].node_type in self._RECOVERABLE}
        committed_values = {item for item in contaminated
                            if self._nodes[item].committed
                            and self._nodes[item].node_type in self._RECOVERABLE}
        affected_transactions = sorted({self._nodes[item].transaction_id
                                        for item in contaminated
                                        if self._nodes[item].transaction_id})
        unrelated = tuple(sorted(item for item, node in self._nodes.items()
                                 if node.committed and node.status is LineageNodeStatus.ACTIVE
                                 and item not in contaminated))
        report = ContaminationReport(
            suspicious_node_id,
            tuple(sorted(self._parents[suspicious_node_id])), tuple(sorted(risky)),
            tuple(sorted(contaminated)), tuple(sorted(committed_values)),
            tuple(sorted(downstream)), tuple(affected_transactions), unrelated,
        )
        self.event_log.record("CONTAMINATION_IDENTIFIED", suspicious_node_id,
                              contaminated_node_ids=report.contaminated_node_ids)
        return report

    def create_recovery_plan(self, report: ContaminationReport) -> RecoveryPlan:
        steps = []
        contaminated = set(report.contaminated_node_ids)
        ordered_contaminated = sorted(contaminated, key=self._ranks.__getitem__)
        recoverable = [item for item in ordered_contaminated
                       if self._nodes[item].node_type in self._RECOVERABLE
                       and self._nodes[item].status is LineageNodeStatus.ACTIVE]
        upstream_recoverable: dict[str, bool] = {}
        recoverable_set = set(recoverable)
        for item in ordered_contaminated:
            upstream_recoverable[item] = any(
                parent in recoverable_set or upstream_recoverable.get(parent, False)
                for parent in self._parents[item] if parent in contaminated
            )
        for item in recoverable:
            action = (RecoveryAction.QUARANTINE
                      if not upstream_recoverable[item]
                      else RecoveryAction.INVALIDATE)
            steps.append(RecoveryStep(item, action, "explicit contaminated lineage"))
        steps.extend(RecoveryStep(item, RecoveryAction.PRESERVE, "outside contaminated lineage")
                     for item in report.unrelated_committed_ids
                     if self._nodes[item].node_type in self._RECOVERABLE)
        plan = RecoveryPlan(report.suspicious_node_id, self._revision, tuple(steps))
        self.event_log.record("RECOVERY_PLAN_CREATED", report.suspicious_node_id,
                              graph_revision=self._revision, steps=len(steps))
        return plan

    def apply_recovery(self, plan: RecoveryPlan, sessions: Any) -> RecoveryResult:
        if plan.graph_revision != self._revision:
            raise TransactionError("stale recovery plan does not match graph revision")
        quarantined, invalidated, preserved = [], [], []
        for step in plan.steps:
            node = self._nodes[step.node_id]
            if step.action is RecoveryAction.PRESERVE:
                preserved.append(node.node_id); continue
            if node.state_reference is None:
                continue
            if step.action is RecoveryAction.QUARANTINE:
                value = _read_reference(sessions, node.state_reference)
                node.status = LineageNodeStatus.QUARANTINED
                self._quarantine[node.node_id] = RecoveryQuarantineEntry(
                    node.node_id, deepcopy(value), deepcopy(node), step.reason)
                quarantined.append(node.node_id); event = "STATE_QUARANTINED"
            else:
                node.status = LineageNodeStatus.INVALIDATED
                invalidated.append(node.node_id); event = "STATE_INVALIDATED"
            self.event_log.record(event, plan.suspicious_node_id,
                                  session_id=node.session_id, node_id=node.node_id)
        self._revision += 1
        self.event_log.record("RECOVERY_APPLIED", plan.suspicious_node_id,
                              quarantined_ids=quarantined, invalidated_ids=invalidated)
        return RecoveryResult(tuple(quarantined), tuple(invalidated), tuple(preserved))

    def assert_readable(self, session_id: str, path: FieldPath) -> None:
        requested = path.canonical()
        for (owner, registered), node_id in self._references.items():
            if owner != session_id or not (
                requested == registered or requested.startswith(registered + "/")
                or registered.startswith(requested + "/")
            ):
                continue
            status = self._nodes[node_id].status
            if status is not LineageNodeStatus.ACTIVE:
                raise TransactionError(f"lineage state is not readable ({status.value})")

    def trusted_quarantine(self, node_id: str) -> RecoveryQuarantineEntry:
        return deepcopy(self._quarantine[node_id])

    def estimated_bytes(self) -> int:
        document = {"nodes": [vars(node) for node in self._nodes.values()],
                    "edges": [vars(edge) for edge in self._edges.values()]}
        return len(json.dumps(document, default=repr, sort_keys=True,
                              separators=(",", ":")).encode())

    def accounting(self) -> dict[str, int]:
        return {"nodes": len(self._nodes), "edges": len(self._edges),
                "estimated_bytes": self.estimated_bytes(), "revision": self._revision}

    def _walk(self, node_id: str, adjacency: dict[str, set[str]]) -> tuple[str, ...]:
        self.get(node_id); visited: set[str] = set(); ordered: list[str] = []
        queue = deque(sorted(adjacency[node_id]))
        while queue:
            item = queue.popleft()
            if item in visited: continue
            visited.add(item); ordered.append(item)
            queue.extend(sorted(adjacency[item] - visited))
        return tuple(ordered)

    def _origins(self, node_id: str, attribute: str) -> tuple[str, ...]:
        candidates = [self._nodes[item] for item in (*self.ancestor_ids(node_id), node_id)]
        roots = [node for node in candidates if node.source_id is not None
                 and not self._parents[node.node_id]]
        return tuple(sorted({getattr(node, attribute) for node in roots
                             if getattr(node, attribute) is not None}))


def _read_reference(sessions: Any, reference: StateReference) -> Any:
    value = getattr(sessions.get_session(reference.session_id), reference.path.field_name)
    for component in reference.path.components:
        value = value[component.value]
    return deepcopy(value)
