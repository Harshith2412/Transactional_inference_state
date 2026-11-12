"""Runtime-issued immutable provenance records with lightweight lineage."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol


class RuntimeSourceType(str, Enum):
    USER_INPUT = "USER_INPUT"
    USER_PROMPT = "USER_PROMPT"
    RETRIEVED_CONTENT = "RETRIEVED_CONTENT"
    TOOL_RESULT = "TOOL_RESULT"
    MODEL_OUTPUT = "MODEL_OUTPUT"
    MEMORY = "MEMORY"
    SYSTEM_CONTEXT = "SYSTEM_CONTEXT"
    DERIVED_VALUE = "DERIVED_VALUE"


class TrustLabel(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    MIXED = "MIXED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RuntimeProvenanceRecord:
    source_id: str
    source_type: RuntimeSourceType
    origin_session: str
    origin_transaction: str | None
    parent_source_ids: tuple[str, ...]
    created_by_runtime: bool = True
    user_id: str = "unknown"
    trust_label: TrustLabel = TrustLabel.UNKNOWN
    committed: bool = True


@dataclass(frozen=True)
class ProvenanceLabel:
    """Authoritative identity and trust metadata issued by the runtime."""

    user_id: str
    session_id: str
    transaction_id: str
    source_id: str
    source_type: RuntimeSourceType
    trust_label: TrustLabel


@dataclass(frozen=True)
class ProvenancedValue:
    """A value paired with one or more authoritative runtime source records."""

    value: Any
    provenance: tuple[ProvenanceLabel, ...]


@dataclass(frozen=True)
class ProvenancePolicyContext:
    transaction_id: str
    session_id: str
    destination: str
    sources: tuple[RuntimeProvenanceRecord, ...]


@dataclass(frozen=True)
class ProvenancePolicyDecision:
    allowed: bool
    reasons: tuple[str, ...] = ()


class ProvenancePolicyHook(Protocol):
    """Optional policy interface; PolicyV1 and PolicyV2 remain unchanged."""

    def evaluate_provenance(
        self, context: ProvenancePolicyContext
    ) -> ProvenancePolicyDecision: ...


@dataclass(frozen=True)
class RuntimeMemoryLineage:
    memory_entry_id: str
    runtime_source_ids: tuple[str, ...]
    source_types: tuple[RuntimeSourceType, ...]
    origin_transaction: str
    origin_session: str


class ProvenanceRegistry:
    """Issues immutable, deterministic source IDs and verifies lineage references."""

    def __init__(self) -> None:
        self._records: dict[str, RuntimeProvenanceRecord] = {}
        self._tentative: dict[str, dict[str, RuntimeProvenanceRecord]] = {}
        self._next_id = 1

    def issue(self, source_type: RuntimeSourceType, *, origin_session: str,
              origin_transaction: str | None = None,
              parent_source_ids: tuple[str, ...] = ()) -> RuntimeProvenanceRecord:
        unknown = set(parent_source_ids) - set(self._records)
        if unknown:
            raise ValueError(f"unknown provenance parents: {sorted(unknown)}")
        source_id = f"source-{self._next_id:06d}"
        self._next_id += 1
        record = RuntimeProvenanceRecord(
            source_id, source_type, origin_session, origin_transaction,
            tuple(parent_source_ids), True,
        )
        self._records[source_id] = record
        return record

    def issue_tentative(
        self, source_type: RuntimeSourceType, *, user_id: str,
        origin_session: str, origin_transaction: str,
        trust_label: TrustLabel = TrustLabel.UNKNOWN,
        parent_source_ids: tuple[str, ...] = (),
    ) -> RuntimeProvenanceRecord:
        """Issue a runtime-owned node that exists only inside one transaction."""
        if not all((user_id, origin_session, origin_transaction)):
            raise ValueError("provenance identity fields must be non-empty")
        known = set(self._records) | set(self._tentative.get(origin_transaction, {}))
        unknown = set(parent_source_ids) - known
        if unknown:
            raise ValueError(f"unknown provenance parents: {sorted(unknown)}")
        source_id = f"source-{self._next_id:06d}"
        self._next_id += 1
        record = RuntimeProvenanceRecord(
            source_id, source_type, origin_session, origin_transaction,
            tuple(parent_source_ids), True, user_id, trust_label, False,
        )
        self._tentative.setdefault(origin_transaction, {})[source_id] = record
        return record

    def commit_transaction(self, transaction_id: str) -> tuple[RuntimeProvenanceRecord, ...]:
        records = self._tentative.pop(transaction_id, {})
        committed = tuple(RuntimeProvenanceRecord(
            record.source_id, record.source_type, record.origin_session,
            record.origin_transaction, record.parent_source_ids,
            record.created_by_runtime, record.user_id, record.trust_label, True,
        ) for record in records.values())
        self._records.update({record.source_id: record for record in committed})
        return committed

    def discard_transaction(self, transaction_id: str) -> tuple[RuntimeProvenanceRecord, ...]:
        return tuple(self._tentative.pop(transaction_id, {}).values())

    def resolve_transaction(
        self, transaction_id: str, committed_source_ids: tuple[str, ...]
    ) -> tuple[tuple[RuntimeProvenanceRecord, ...], tuple[RuntimeProvenanceRecord, ...]]:
        """Commit an explicit lineage closure and discard all other tentative nodes."""
        records = self._tentative.pop(transaction_id, {})
        selected = set(committed_source_ids)
        unknown = selected - set(records)
        if unknown:
            raise ValueError(f"sources are not tentative for transaction: {sorted(unknown)}")
        committed = tuple(
            RuntimeProvenanceRecord(
                record.source_id, record.source_type, record.origin_session,
                record.origin_transaction, record.parent_source_ids,
                record.created_by_runtime, record.user_id, record.trust_label, True,
            )
            for record in records.values() if record.source_id in selected
        )
        discarded = tuple(
            record for record in records.values() if record.source_id not in selected
        )
        self._records.update({record.source_id: record for record in committed})
        return committed, discarded

    def labels(self, source_ids: tuple[str, ...]) -> tuple[ProvenanceLabel, ...]:
        return tuple(ProvenanceLabel(
            record.user_id, record.origin_session,
            record.origin_transaction or "outside-transaction", record.source_id,
            record.source_type, record.trust_label,
        ) for record in (self.get(source_id) for source_id in source_ids))

    def is_tentative_for(self, source_id: str, transaction_id: str) -> bool:
        return source_id in self._tentative.get(transaction_id, {})

    def contains(self, source_id: str) -> bool:
        return source_id in self._records or any(
            source_id in records for records in self._tentative.values()
        )

    def get(self, source_id: str) -> RuntimeProvenanceRecord:
        if source_id in self._records:
            return self._records[source_id]
        for records in self._tentative.values():
            if source_id in records:
                return records[source_id]
        raise KeyError(f"unknown runtime source: {source_id}")

    def lineage(self, source_ids: tuple[str, ...]) -> tuple[RuntimeProvenanceRecord, ...]:
        visited: dict[str, RuntimeProvenanceRecord] = {}

        def visit(source_id: str) -> None:
            record = self.get(source_id)
            if source_id in visited:
                return
            visited[source_id] = record
            for parent in record.parent_source_ids:
                visit(parent)

        for source_id in source_ids:
            visit(source_id)
        return tuple(visited.values())

    def root_sources(self, source_ids: tuple[str, ...]) -> tuple[RuntimeProvenanceRecord, ...]:
        lineage = self.lineage(source_ids)
        return tuple(record for record in lineage if not record.parent_source_ids)

    def origin_users(self, source_ids: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({record.user_id for record in self.root_sources(source_ids)}))

    def origin_sessions(self, source_ids: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({record.origin_session for record in self.root_sources(source_ids)}))

    def origin_transactions(self, source_ids: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({record.origin_transaction for record in self.root_sources(source_ids)
                             if record.origin_transaction is not None}))

    def origin_sources(self, source_ids: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(record.source_id for record in self.root_sources(source_ids)))
