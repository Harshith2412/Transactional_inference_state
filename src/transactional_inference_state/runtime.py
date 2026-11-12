"""Core primitives for deterministic transactional inference state."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field, fields
from enum import Enum
import json
import threading
from typing import Any, Callable, Protocol

from .provenance import (
    ProvenancePolicyContext, ProvenancePolicyDecision, ProvenancePolicyHook,
    ProvenanceRegistry, ProvenancedValue, RuntimeProvenanceRecord,
    RuntimeSourceType, TrustLabel,
)


@dataclass
class InferenceState:
    """Mutable private state owned by exactly one session.

    Transaction strategies isolate mutations to these fields until commit.
    Callers must not use an instance as a cross-session capability.
    """
    session_memory: dict[str, Any] = field(default_factory=dict)
    scratchpad: list[Any] = field(default_factory=list)
    application_cache: dict[str, Any] = field(default_factory=dict)
    retrieved_data: list[Any] = field(default_factory=list)
    tool_results: list[Any] = field(default_factory=list)
    pending_memory_writes: list[Any] = field(default_factory=list)
    user_session_metadata: dict[str, Any] = field(default_factory=dict)
    security_state: dict[str, Any] = field(default_factory=dict)
    memory_lineage: dict[str, Any] = field(default_factory=dict)
    provenance_metadata: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class Event:
    sequence: int
    event_type: str
    transaction_id: str
    details: dict[str, Any] = field(default_factory=dict)
    session_id: str | None = None


class EventLog:
    """Append-only in-memory audit log with copied event details."""
    def __init__(self) -> None:
        self._events: list[Event] = []

    @property
    def events(self) -> tuple[Event, ...]:
        return tuple(self._events)

    def record(self, event_type: str, transaction_id: str, *,
               session_id: str | None = None, **details: Any) -> Event:
        event = Event(len(self._events) + 1, event_type, transaction_id,
                      deepcopy(details), session_id)
        self._events.append(event)
        return event


class SnapshotManager:
    """Stage 1 full-state deepcopy/restore helper preserving object identity."""
    def create(self, state: InferenceState) -> InferenceState:
        return deepcopy(state)

    def restore(self, state: InferenceState, snapshot: InferenceState) -> None:
        for item in fields(InferenceState):
            setattr(state, item.name, deepcopy(getattr(snapshot, item.name)))


class SnapshotStrategy(Protocol):
    """Private-state transaction storage strategy."""

    name: str

    def begin(self, state: InferenceState) -> Any: ...
    def materialize(self, context: Any) -> InferenceState: ...
    def read(self, context: Any, field_name: str, key: Any) -> Any: ...
    def write(self, context: Any, field_name: str, key: Any, value: Any) -> None: ...
    def delete(self, context: Any, field_name: str, key: Any) -> None: ...
    def commit(self, context: Any, state: InferenceState) -> None: ...


class FullCopyStrategy:
    """Eagerly deep-copies the complete private state at transaction start."""

    name = "full_copy"

    def begin(self, state: InferenceState) -> InferenceState:
        return deepcopy(state)

    def materialize(self, context: InferenceState) -> InferenceState:
        return context

    def read(self, context: InferenceState, field_name: str, key: Any) -> Any:
        return deepcopy(getattr(context, field_name)[key])

    def write(self, context: InferenceState, field_name: str,
              key: Any, value: Any) -> None:
        getattr(context, field_name)[key] = deepcopy(value)

    def delete(self, context: InferenceState, field_name: str, key: Any) -> None:
        del getattr(context, field_name)[key]

    def commit(self, context: InferenceState, state: InferenceState) -> None:
        SnapshotManager().restore(state, context)


@dataclass
class DeltaContext:
    """Key-level overlay; ``base`` remains committed and must not be mutated."""
    base: InferenceState
    writes: dict[str, dict[Any, Any]] = field(default_factory=dict)
    deletes: dict[str, set[Any]] = field(default_factory=dict)
    materialized: InferenceState | None = None


@dataclass(frozen=True)
class DeltaAccounting:
    approximate_delta_bytes: int
    changed_keys: int
    deletions: int
    materialized_state_bytes: int | None


class DeltaStrategy:
    """Tracks key-level replacements and deletions without copying at begin."""

    name = "delta"

    def begin(self, state: InferenceState) -> DeltaContext:
        return DeltaContext(base=state)

    def materialize(self, context: DeltaContext) -> InferenceState:
        if context.materialized is None:
            context.materialized = deepcopy(context.base)
            self._apply_delta(context, context.materialized)
        return context.materialized

    def read(self, context: DeltaContext, field_name: str, key: Any) -> Any:
        if context.materialized is not None:
            return deepcopy(getattr(context.materialized, field_name)[key])
        if key in context.deletes.get(field_name, set()):
            raise KeyError(key)
        if key in context.writes.get(field_name, {}):
            return deepcopy(context.writes[field_name][key])
        return deepcopy(getattr(context.base, field_name)[key])

    def write(self, context: DeltaContext, field_name: str,
              key: Any, value: Any) -> None:
        if context.materialized is not None:
            getattr(context.materialized, field_name)[key] = deepcopy(value)
            return
        context.writes.setdefault(field_name, {})[key] = deepcopy(value)
        context.deletes.setdefault(field_name, set()).discard(key)

    def delete(self, context: DeltaContext, field_name: str, key: Any) -> None:
        if context.materialized is not None:
            del getattr(context.materialized, field_name)[key]
            return
        # Match normal container deletion semantics.
        self.read(context, field_name, key)
        context.writes.setdefault(field_name, {}).pop(key, None)
        context.deletes.setdefault(field_name, set()).add(key)

    def commit(self, context: DeltaContext, state: InferenceState) -> None:
        if context.materialized is not None:
            SnapshotManager().restore(state, context.materialized)
        else:
            self._apply_delta(context, state)

    def accounting(self, context: DeltaContext) -> DeltaAccounting:
        encoded = json.dumps(context.writes, sort_keys=True, default=repr,
                             separators=(",", ":")).encode("utf-8")
        materialized_bytes = None
        if context.materialized is not None:
            materialized_bytes = len(json.dumps(
                {item.name: getattr(context.materialized, item.name)
                 for item in fields(InferenceState)},
                sort_keys=True, default=repr, separators=(",", ":"),
            ).encode("utf-8"))
        return DeltaAccounting(
            approximate_delta_bytes=len(encoded),
            changed_keys=sum(len(items) for items in context.writes.values()),
            deletions=sum(len(items) for items in context.deletes.values()),
            materialized_state_bytes=materialized_bytes,
        )

    @staticmethod
    def _apply_delta(context: DeltaContext, state: InferenceState) -> None:
        for field_name, keys in context.deletes.items():
            container = getattr(state, field_name)
            for key in keys:
                del container[key]
        for field_name, replacements in context.writes.items():
            container = getattr(state, field_name)
            for key, value in replacements.items():
                container[key] = deepcopy(value)


class PolicyValidator:
    """Deterministic fixed or state-callable commit policy.

    A ``True`` result authorizes commit; this prototype does not claim the
    policy is a complete semantic security classifier.
    """
    def __init__(self, accept: bool | Callable[[InferenceState], bool] = True) -> None:
        self._decision = accept

    def validate(self, state: InferenceState) -> bool:
        result = self._decision(state) if callable(self._decision) else self._decision
        return bool(result)

    @property
    def requires_state(self) -> bool:
        return callable(self._decision)

    def fixed_result(self) -> bool:
        if self.requires_state:
            raise TypeError("callable policy requires state")
        return bool(self._decision)


class TransactionError(RuntimeError):
    """Raised for unknown transactions, ownership errors, or invalid transitions."""


class WriteConflictError(TransactionError):
    """Raised before shared writes apply when an observed version is stale."""


class TransactionStatus(str, Enum):
    ACTIVE = "active"
    VALIDATED = "validated"
    REJECTED = "rejected"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    ABORTED = "aborted"
    PARTIAL_EFFECT_FAILURE = "partial_effect_failure"
    EXTERNAL_ROLLBACK_FAILED = "external_rollback_failed"
    PARTIALLY_COMMITTED = "partially_committed"
    QUARANTINED = "quarantined"
    REVIEW_REQUIRED = "review_required"


@dataclass(frozen=True)
class VersionedValue:
    value: Any
    version: int
    provenance_ids: tuple[str, ...] = ()
    field_provenance: tuple[tuple[str, tuple[str, ...]], ...] = ()


class SharedState:
    """Committed application state with per-key integer versions."""
    def __init__(self, initial: dict[str, Any] | None = None) -> None:
        self._entries = {key: VersionedValue(deepcopy(value), 0, (), ())
                         for key, value in (initial or {}).items()}
        self._lock = threading.RLock()

    def read(self, key: str) -> VersionedValue:
        with self._lock:
            try:
                entry = self._entries[key]
            except KeyError as error:
                raise KeyError(f"unknown shared-state key: {key}") from error
            return VersionedValue(
                deepcopy(entry.value), entry.version, entry.provenance_ids,
                tuple((field, tuple(ids)) for field, ids in entry.field_provenance),
            )

    def apply(self, writes: dict[str, Any], versions: dict[str, int],
              provenance: dict[str, tuple[str, ...]] | None = None,
              field_provenance: dict[str, dict[str, tuple[str, ...]]] | None = None,
              ) -> None:
        with self._lock:
            for key in writes:
                actual = self._entries[key].version if key in self._entries else -1
                if versions[key] != actual:
                    raise WriteConflictError(
                        f"shared-state conflict for {key!r}: expected version "
                        f"{versions[key]}, found {actual}"
                    )
            for key, value in writes.items():
                old = self._entries[key].version if key in self._entries else -1
                fields_for_key = (field_provenance or {}).get(key, {})
                self._entries[key] = VersionedValue(
                    deepcopy(value), old + 1, tuple((provenance or {}).get(key, ())),
                    tuple(sorted((field, tuple(ids))
                                 for field, ids in fields_for_key.items())),
                )


class SessionManager:
    """Registry that allocates a distinct private state object per session ID."""
    def __init__(self) -> None:
        self._sessions: dict[str, InferenceState] = {}
        self._users: dict[str, str] = {}

    def create_session(self, session_id: str, *, user_id: str | None = None) -> InferenceState:
        if not session_id:
            raise ValueError("session_id must not be empty")
        if session_id in self._sessions:
            raise ValueError(f"session already exists: {session_id}")
        state = InferenceState()
        self._sessions[session_id] = state
        self._users[session_id] = user_id or session_id
        return state

    def get_session(self, session_id: str) -> InferenceState:
        try:
            return self._sessions[session_id]
        except KeyError as error:
            raise KeyError(f"unknown session: {session_id}") from error

    def user_id(self, session_id: str) -> str:
        self.get_session(session_id)
        return self._users[session_id]


@dataclass
class Transaction:
    """Addressable lifecycle record and private/shared transaction context."""
    transaction_id: str
    session_id: str
    status: TransactionStatus
    snapshot: InferenceState | None
    local_state: InferenceState | None
    strategy_context: Any = None
    read_set: dict[str, int] = field(default_factory=dict)
    write_set: dict[str, Any] = field(default_factory=dict)
    shared_provenance: dict[str, tuple[str, ...]] = field(default_factory=dict)
    shared_field_provenance: dict[str, dict[str, tuple[str, ...]]] = field(default_factory=dict)
    validated: bool | None = None


class TransactionManager:
    """Manages concurrent transactions; an InferenceState enables Stage 1 mode."""
    def __init__(self, state: InferenceState | SessionManager, *,
                 shared_state: SharedState | None = None,
                 snapshot_strategy: SnapshotStrategy | None = None,
                 effect_manager: Any | None = None,
                 snapshot_manager: SnapshotManager | None = None,
                 event_log: EventLog | None = None,
                 validator: PolicyValidator | None = None,
                 failure_injector: Any | None = None,
                 provenance_registry: ProvenanceRegistry | None = None,
                 lineage_graph: Any | None = None) -> None:
        self.snapshot_manager = snapshot_manager or SnapshotManager()
        self.event_log = event_log or EventLog()
        self.validator = validator or PolicyValidator()
        self.shared_state = shared_state or SharedState()
        self.snapshot_strategy = snapshot_strategy or FullCopyStrategy()
        self.effect_manager = effect_manager
        self.failure_injector = failure_injector
        self.provenance_registry = provenance_registry or ProvenanceRegistry()
        self.lineage_graph = lineage_graph
        self._next_transaction_number = 1
        self._transactions: dict[str, Transaction] = {}
        self._legacy = isinstance(state, InferenceState)
        self.state = state if self._legacy else None
        self.sessions = state if isinstance(state, SessionManager) else None
        if self.effect_manager is not None:
            self.effect_manager.bind(self)

    @property
    def active_transaction_id(self) -> str | None:
        active = [tx.transaction_id for tx in self._transactions.values()
                  if tx.status in self._open_statuses()]
        return active[0] if len(active) == 1 else None

    def begin(self, session_id: str | None = None) -> str:
        if self._legacy:
            if not isinstance(self.snapshot_strategy, FullCopyStrategy):
                raise ValueError("Stage 1 compatibility mode requires FullCopyStrategy")
            if self.active_transaction_id is not None:
                raise TransactionError("a transaction is already active")
            session_id, committed = session_id or "legacy", self.state
        else:
            if session_id is None:
                raise TransactionError("session_id is required")
            committed = self.sessions.get_session(session_id)
        txid = f"txn-{self._next_transaction_number:06d}"
        self._next_transaction_number += 1
        snapshot = self.snapshot_manager.create(committed) if self._legacy else None
        context = self.snapshot_strategy.begin(committed)
        local = committed if self._legacy else (
            context if isinstance(context, InferenceState) else None
        )
        self._transactions[txid] = Transaction(
            txid, session_id, TransactionStatus.ACTIVE, snapshot, local,
            strategy_context=context)
        self.event_log.record("transaction_begin", txid,
                              session_id=None if self._legacy else session_id)
        self._trigger_failure("AFTER_BEGIN")
        return txid

    def transaction_state(self, transaction_id: str, session_id: str) -> InferenceState:
        tx = self._require_open(transaction_id)
        self._require_owner(tx, session_id)
        if tx.local_state is None:
            tx.local_state = self.snapshot_strategy.materialize(tx.strategy_context)
        return tx.local_state

    def mutate(self, transaction_id: str, session_id: str,
               mutation: Callable[[InferenceState], None], *,
               description: str = "private state mutation") -> None:
        tx = self._require_open(transaction_id)
        self._require_owner(tx, session_id)
        mutation(self.transaction_state(transaction_id, session_id))
        self.event_log.record("state_mutation", transaction_id,
                              session_id=session_id, description=description)
        self._trigger_failure("AFTER_MUTATION")

    def read_private(self, transaction_id: str, session_id: str,
                     field_name: str, key: Any) -> Any:
        tx = self._require_open(transaction_id)
        self._require_owner(tx, session_id)
        self._require_container_field(field_name)
        if self.lineage_graph is not None:
            from .cow import FieldPath, DictKey, ListIndex
            component = DictKey(key) if isinstance(key, str) else ListIndex(key)
            self.lineage_graph.assert_readable(
                session_id, FieldPath(field_name, (component,))
            )
        return self.snapshot_strategy.read(tx.strategy_context, field_name, key)

    def read_private_provenanced(self, transaction_id: str, session_id: str,
                                 field_name: str, key: str) -> ProvenancedValue:
        value = self.read_private(transaction_id, session_id, field_name, key)
        metadata_key = self._provenance_key(field_name, key)
        try:
            source_ids = tuple(self.snapshot_strategy.read(
                self._get(transaction_id).strategy_context,
                "provenance_metadata", metadata_key,
            ))
        except KeyError:
            source_ids = ()
        self.event_log.record(
            "PROVENANCE_READ", transaction_id, session_id=session_id,
            field=field_name, key=key, source_ids=source_ids,
        )
        return ProvenancedValue(value, self.provenance_registry.labels(source_ids))

    def read_path(self, transaction_id: str, session_id: str,
                  path: Any) -> Any:
        tx = self._require_open(transaction_id)
        self._require_owner(tx, session_id)
        self._require_container_field(path.field_name)
        if self.lineage_graph is not None:
            self.lineage_graph.assert_readable(session_id, path)
        reader = getattr(self.snapshot_strategy, "read_path", None)
        if reader is None:
            raise TransactionError(
                "structured paths require FineGrainedCOWStrategy"
            )
        return reader(tx.strategy_context, path)

    def read_path_provenanced(self, transaction_id: str, session_id: str,
                              path: Any) -> ProvenancedValue:
        value = self.read_path(transaction_id, session_id, path)
        tx = self._get(transaction_id)
        metadata_key = path.canonical()
        try:
            source_ids = tuple(self.snapshot_strategy.read(
                tx.strategy_context, "provenance_metadata", metadata_key
            ))
        except KeyError:
            source_ids = ()
        self.event_log.record(
            "PROVENANCE_READ", transaction_id, session_id=session_id,
            path=metadata_key, source_ids=source_ids,
        )
        return ProvenancedValue(value, self.provenance_registry.labels(source_ids))

    def write_path(self, transaction_id: str, session_id: str, path: Any,
                   value: Any, *, provenance_ids: tuple[str, ...] = ()) -> None:
        tx = self._require_open(transaction_id)
        self._require_owner(tx, session_id)
        self._require_container_field(path.field_name)
        writer = getattr(self.snapshot_strategy, "write_path", None)
        if writer is None:
            raise TransactionError(
                "structured paths require FineGrainedCOWStrategy"
            )
        if provenance_ids:
            self._require_authoritative_provenance(tx, provenance_ids)
        writer(tx.strategy_context, path, value)
        if provenance_ids:
            self.snapshot_strategy.write(
                tx.strategy_context, "provenance_metadata", path.canonical(),
                tuple(provenance_ids),
            )
        self.event_log.record(
            "state_mutation", transaction_id, session_id=session_id,
            operation="path_write", path=path.canonical(),
        )
        self._trigger_failure("AFTER_MUTATION")

    def delete_path(self, transaction_id: str, session_id: str,
                    path: Any) -> None:
        tx = self._require_open(transaction_id)
        self._require_owner(tx, session_id)
        self._require_container_field(path.field_name)
        deleter = getattr(self.snapshot_strategy, "delete_path", None)
        if deleter is None:
            raise TransactionError(
                "structured paths require FineGrainedCOWStrategy"
            )
        deleter(tx.strategy_context, path)
        try:
            self.snapshot_strategy.delete(
                tx.strategy_context, "provenance_metadata", path.canonical()
            )
        except KeyError:
            pass
        self.event_log.record(
            "state_mutation", transaction_id, session_id=session_id,
            operation="path_delete", path=path.canonical(),
        )
        self._trigger_failure("AFTER_MUTATION")

    def write_private(self, transaction_id: str, session_id: str,
                      field_name: str, key: Any, value: Any, *,
                      provenance_ids: tuple[str, ...] = ()) -> None:
        tx = self._require_open(transaction_id)
        self._require_owner(tx, session_id)
        self._require_container_field(field_name)
        if provenance_ids:
            self._require_authoritative_provenance(tx, provenance_ids)
        self.snapshot_strategy.write(tx.strategy_context, field_name, key, value)
        if provenance_ids:
            metadata_key = self._provenance_key(field_name, key)
            self.snapshot_strategy.write(
                tx.strategy_context, "provenance_metadata", metadata_key,
                tuple(provenance_ids),
            )
        self.event_log.record("state_mutation", transaction_id,
                              session_id=session_id, operation="write",
                              field=field_name, key=key)
        self._trigger_failure("AFTER_MUTATION")

    def delete_private(self, transaction_id: str, session_id: str,
                       field_name: str, key: Any) -> None:
        tx = self._require_open(transaction_id)
        self._require_owner(tx, session_id)
        self._require_container_field(field_name)
        self.snapshot_strategy.delete(tx.strategy_context, field_name, key)
        metadata_key = self._provenance_key(field_name, key)
        try:
            self.snapshot_strategy.delete(
                tx.strategy_context, "provenance_metadata", metadata_key
            )
        except KeyError:
            pass
        self.event_log.record("state_mutation", transaction_id,
                              session_id=session_id, operation="delete",
                              field=field_name, key=key)
        self._trigger_failure("AFTER_MUTATION")

    def record_mutation(self, description: str,
                        transaction_id: str | None = None, **details: Any) -> None:
        tx = self._resolve_open(transaction_id)
        self.event_log.record("state_mutation", tx.transaction_id,
                              session_id=None if self._legacy else tx.session_id,
                              description=description, **details)

    def read_shared(self, transaction_id: str, key: str) -> Any:
        tx = self._require_open(transaction_id)
        if key in tx.write_set:
            value, version = deepcopy(tx.write_set[key]), tx.read_set[key]
        else:
            entry = self.shared_state.read(key)
            value, version = entry.value, entry.version
            tx.read_set.setdefault(key, version)
        self.event_log.record("shared_state_read", transaction_id,
                              session_id=tx.session_id, key=key, version=version)
        return value

    def read_shared_provenanced(self, transaction_id: str, key: str) -> ProvenancedValue:
        tx = self._require_open(transaction_id)
        value = self.read_shared(transaction_id, key)
        if key in tx.write_set:
            source_ids = tx.shared_provenance.get(key, ())
        else:
            source_ids = self.shared_state.read(key).provenance_ids
        self.event_log.record(
            "PROVENANCE_READ", transaction_id, session_id=tx.session_id,
            destination="shared_state", key=key, source_ids=source_ids,
        )
        return ProvenancedValue(value, self.provenance_registry.labels(source_ids))

    def write_shared(self, transaction_id: str, key: str, value: Any, *,
                     provenance_ids: tuple[str, ...] = ()) -> None:
        tx = self._require_open(transaction_id)
        if provenance_ids:
            self._require_authoritative_provenance(tx, provenance_ids)
        if key not in tx.read_set:
            try:
                tx.read_set[key] = self.shared_state.read(key).version
            except KeyError:
                tx.read_set[key] = -1
        tx.write_set[key] = deepcopy(value)
        if provenance_ids:
            tx.shared_provenance[key] = tuple(provenance_ids)
        self.event_log.record("shared_state_tentative_write", transaction_id,
                              session_id=tx.session_id, key=key,
                              observed_version=tx.read_set[key])

    def write_shared_object(
        self, transaction_id: str, key: str, value: dict[str, Any], *,
        field_provenance: dict[str, tuple[str, ...]],
    ) -> None:
        if not isinstance(value, dict):
            raise TypeError("field-level shared values must be dictionaries")
        unknown_fields = set(field_provenance) - set(value)
        if unknown_fields:
            raise ValueError(f"provenance supplied for unknown fields: {sorted(unknown_fields)}")
        tx = self._require_open(transaction_id)
        for source_ids in field_provenance.values():
            self._require_authoritative_provenance(tx, tuple(source_ids))
        self.write_shared(transaction_id, key, value)
        tx.shared_field_provenance[key] = {
            field: tuple(source_ids)
            for field, source_ids in field_provenance.items()
        }
        self.event_log.record(
            "SHARED_FIELD_PROVENANCE_ATTACHED", transaction_id,
            session_id=tx.session_id, key=key,
            fields=sorted(field_provenance),
        )

    def read_shared_fields(
        self, transaction_id: str, key: str, requested_fields: tuple[str, ...], *,
        flow_policy: Any, current_principal: Any, destination_scope: str,
        capability: Any | None = None,
    ) -> Any:
        from .flow import FlowResourceScope
        tx = self._require_open(transaction_id)
        if tx.session_id != current_principal.session_id:
            raise TransactionError("current principal does not own transaction")
        if key in tx.write_set:
            value = deepcopy(tx.write_set[key])
            field_sources = tx.shared_field_provenance.get(key, {})
        else:
            entry = self.shared_state.read(key)
            value = entry.value
            field_sources = dict(entry.field_provenance)
            tx.read_set.setdefault(key, entry.version)
        result = flow_policy.filter_fields(
            value=value, field_provenance=field_sources,
            requested_fields=requested_fields, current=current_principal,
            scope=FlowResourceScope(f"shared:{key}", destination_scope),
            capability=capability,
        )
        for field_name, decision in result.decisions.items():
            self.event_log.record(
                decision.outcome.value, transaction_id,
                session_id=tx.session_id, key=key, field=field_name,
                allowed=decision.allowed, source_ids=decision.source_ids,
            )
        return result

    def issue_provenance(
        self, transaction_id: str, source_type: RuntimeSourceType, *,
        trust_label: TrustLabel = TrustLabel.UNKNOWN,
        parent_source_ids: tuple[str, ...] = (),
    ) -> RuntimeProvenanceRecord:
        tx = self._require_open(transaction_id)
        authoritative_user = (
            tx.session_id if self._legacy else self.sessions.user_id(tx.session_id)
        )
        record = self.provenance_registry.issue_tentative(
            source_type, user_id=authoritative_user,
            origin_session=tx.session_id, origin_transaction=tx.transaction_id,
            trust_label=trust_label, parent_source_ids=parent_source_ids,
        )
        event_type = "PROVENANCE_DERIVED" if parent_source_ids else "PROVENANCE_CREATED"
        self.event_log.record(
            event_type, tx.transaction_id, session_id=tx.session_id,
            source_id=record.source_id, source_type=record.source_type.value,
            trust_label=record.trust_label.value,
            parent_source_ids=record.parent_source_ids,
        )
        return record

    def evaluate_provenance(
        self, transaction_id: str, policy: ProvenancePolicyHook, *,
        destination: str, source_ids: tuple[str, ...],
    ) -> ProvenancePolicyDecision:
        tx = self._require_open(transaction_id)
        self._require_authoritative_provenance(tx, source_ids,
                                               allow_committed=True)
        context = ProvenancePolicyContext(
            tx.transaction_id, tx.session_id, destination,
            tuple(self.provenance_registry.get(item) for item in source_ids),
        )
        return policy.evaluate_provenance(context)

    def validate_provenance_ids(self, transaction_id: str,
                                source_ids: tuple[str, ...]) -> None:
        """Reject forged or cross-transaction tentative provenance references."""
        tx = self._require_open(transaction_id)
        self._require_authoritative_provenance(tx, source_ids,
                                               allow_committed=True)

    def validate(self, transaction_id: str | None = None) -> bool:
        tx = self._resolve_open(transaction_id)
        if tx.status is not TransactionStatus.ACTIVE:
            raise TransactionError("transaction has already been validated")
        if self.validator.requires_state:
            local_state = tx.local_state or self.snapshot_strategy.materialize(
                tx.strategy_context)
            tx.local_state = local_state
            tx.validated = self.validator.validate(local_state)
        else:
            tx.validated = self.validator.fixed_result()
        tx.status = (TransactionStatus.VALIDATED if tx.validated
                     else TransactionStatus.REJECTED)
        self.event_log.record("validation", tx.transaction_id,
                              session_id=None if self._legacy else tx.session_id,
                              accepted=tx.validated)
        self._trigger_failure("AFTER_VALIDATION")
        return tx.validated

    def commit(self, transaction_id: str | None = None) -> None:
        tx = self._resolve_open(transaction_id)
        if tx.status is TransactionStatus.ACTIVE:
            raise TransactionError("transaction must be validated before commit")
        if tx.status is TransactionStatus.REJECTED:
            raise TransactionError("a rejected transaction cannot be committed")
        if tx.status is not TransactionStatus.VALIDATED:
            raise TransactionError(f"cannot commit transaction in {tx.status.value} state")
        self._trigger_failure("DURING_INTERNAL_COMMIT")
        try:
            self.shared_state.apply(
                tx.write_set, tx.read_set, tx.shared_provenance,
                tx.shared_field_provenance,
            )
        except WriteConflictError:
            tx.status = TransactionStatus.ABORTED
            discarded = self.provenance_registry.discard_transaction(
                tx.transaction_id
            )
            self._record_provenance_closure(tx, discarded, committed=False)
            self.event_log.record("conflict_detection", tx.transaction_id,
                                  session_id=tx.session_id,
                                  keys=sorted(tx.write_set), outcome="aborted")
            self.event_log.record("rollback", tx.transaction_id,
                                  session_id=tx.session_id)
            raise
        if not self._legacy:
            self.snapshot_strategy.commit(
                tx.strategy_context, self.sessions.get_session(tx.session_id)
            )
        committed_provenance = self.provenance_registry.commit_transaction(
            tx.transaction_id
        )
        self._record_provenance_closure(tx, committed_provenance, committed=True)
        tx.status = TransactionStatus.COMMITTED
        self.event_log.record("commit", tx.transaction_id,
                              session_id=None if self._legacy else tx.session_id)
        self._trigger_failure("AFTER_INTERNAL_COMMIT")
        if self.effect_manager is not None:
            self._trigger_failure("BEFORE_EFFECT_EXECUTION")
            try:
                self.effect_manager.execute_transaction(
                    tx.transaction_id, tx.session_id
                )
            except Exception:
                tx.status = TransactionStatus.PARTIAL_EFFECT_FAILURE
                raise

    def rollback(self, transaction_id: str | None = None) -> None:
        tx = self._resolve_open(transaction_id)
        if self._legacy:
            self.snapshot_manager.restore(self.state, tx.snapshot)
        if self.effect_manager is not None:
            self.effect_manager.discard_transaction(tx.transaction_id, tx.session_id)
        discarded = self.provenance_registry.discard_transaction(tx.transaction_id)
        self._record_provenance_closure(tx, discarded, committed=False)
        tx.status = TransactionStatus.ROLLED_BACK
        self.event_log.record("rollback", tx.transaction_id,
                              session_id=None if self._legacy else tx.session_id)

    def status(self, transaction_id: str) -> TransactionStatus:
        return self._get(transaction_id).status

    def mark_external_rollback_failed(self, transaction_id: str) -> None:
        tx = self._get(transaction_id)
        if tx.status is not TransactionStatus.ROLLED_BACK:
            raise TransactionError("local rollback must complete before external failure")
        tx.status = TransactionStatus.EXTERNAL_ROLLBACK_FAILED

    def mark_external_rollback_recovered(self, transaction_id: str) -> None:
        tx = self._get(transaction_id)
        if tx.status is not TransactionStatus.EXTERNAL_ROLLBACK_FAILED:
            raise TransactionError("external rollback is not awaiting recovery")
        tx.status = TransactionStatus.ROLLED_BACK

    def mark_partially_committed(self, transaction_id: str) -> None:
        """Expose a failed external flush after the local commit boundary."""
        tx = self._get(transaction_id)
        if tx.status is not TransactionStatus.COMMITTED:
            raise TransactionError("local state must be committed before partial status")
        tx.status = TransactionStatus.PARTIALLY_COMMITTED

    def read_set(self, transaction_id: str) -> dict[str, int]:
        return dict(self._get(transaction_id).read_set)

    def write_set(self, transaction_id: str) -> dict[str, Any]:
        return deepcopy(self._get(transaction_id).write_set)

    def provenance_for_private(self, session_id: str, field_name: str,
                               key: str) -> tuple[RuntimeProvenanceRecord, ...]:
        state = self.state if self._legacy else self.sessions.get_session(session_id)
        source_ids = state.provenance_metadata.get(
            self._provenance_key(field_name, key), ()
        )
        return tuple(self.provenance_registry.get(item) for item in source_ids)

    def provenance_for_path(self, session_id: str,
                            path: Any) -> tuple[RuntimeProvenanceRecord, ...]:
        state = self.state if self._legacy else self.sessions.get_session(session_id)
        source_ids = state.provenance_metadata.get(path.canonical(), ())
        return tuple(self.provenance_registry.get(item) for item in source_ids)

    def provenance_for_shared(self, key: str) -> tuple[RuntimeProvenanceRecord, ...]:
        return tuple(self.provenance_registry.get(item)
                     for item in self.shared_state.read(key).provenance_ids)

    def delta_accounting(self, transaction_id: str) -> DeltaAccounting:
        tx = self._get(transaction_id)
        if not isinstance(self.snapshot_strategy, DeltaStrategy):
            raise TransactionError("delta accounting requires DeltaStrategy")
        return self.snapshot_strategy.accounting(tx.strategy_context)

    def cow_accounting(self, transaction_id: str) -> Any:
        tx = self._get(transaction_id)
        accounting = getattr(self.snapshot_strategy, "accounting", None)
        if self.snapshot_strategy.name != "fine_grained_cow" or accounting is None:
            raise TransactionError(
                "COW accounting requires FineGrainedCOWStrategy"
            )
        return accounting(tx.strategy_context)

    def _trigger_failure(self, point_name: str) -> None:
        if self.failure_injector is None:
            return
        from .failure import FailurePoint
        self.failure_injector.trigger(FailurePoint(point_name))

    def _require_authoritative_provenance(
        self, tx: Transaction, source_ids: tuple[str, ...], *,
        allow_committed: bool = True,
    ) -> None:
        for source_id in source_ids:
            try:
                record = self.provenance_registry.get(source_id)
            except KeyError as error:
                raise TransactionError(
                    "provenance was not issued by the runtime"
                ) from error
            if not record.created_by_runtime:
                raise TransactionError("provenance was not issued by the runtime")
            if not record.committed and not self.provenance_registry.is_tentative_for(
                source_id, tx.transaction_id
            ):
                raise TransactionError("tentative provenance belongs to another transaction")
            if record.committed and not allow_committed:
                raise TransactionError("committed provenance is not allowed here")

    def _record_provenance_closure(
        self, tx: Transaction, records: tuple[RuntimeProvenanceRecord, ...], *,
        committed: bool,
    ) -> None:
        event_type = "PROVENANCE_COMMITTED" if committed else "PROVENANCE_DISCARDED"
        for record in records:
            self.event_log.record(
                event_type, tx.transaction_id, session_id=tx.session_id,
                source_id=record.source_id,
            )

    @staticmethod
    def _provenance_key(field_name: str, key: str) -> str:
        if not isinstance(key, str):
            raise TypeError("provenance-bearing keys must be strings")
        return f"{field_name}:{key}"

    def _get(self, transaction_id: str) -> Transaction:
        try:
            return self._transactions[transaction_id]
        except KeyError as error:
            raise TransactionError(f"unknown transaction: {transaction_id}") from error

    def _resolve_open(self, transaction_id: str | None) -> Transaction:
        if transaction_id is not None:
            return self._require_open(transaction_id)
        active = [tx for tx in self._transactions.values()
                  if tx.status in self._open_statuses()]
        if not active:
            raise TransactionError("no transaction is active")
        if len(active) > 1:
            raise TransactionError(
                "transaction_id is required when multiple transactions are active")
        return active[0]

    def _require_open(self, transaction_id: str) -> Transaction:
        tx = self._get(transaction_id)
        if tx.status not in self._open_statuses():
            raise TransactionError(f"transaction is closed ({tx.status.value})")
        return tx

    @staticmethod
    def _require_owner(tx: Transaction, session_id: str) -> None:
        if tx.session_id != session_id:
            raise TransactionError("transaction does not belong to this session")

    @staticmethod
    def _require_container_field(field_name: str) -> None:
        valid = {item.name for item in fields(InferenceState)}
        if field_name not in valid:
            raise ValueError(f"unknown InferenceState field: {field_name}")

    @staticmethod
    def _open_statuses() -> tuple[TransactionStatus, ...]:
        return (TransactionStatus.ACTIVE, TransactionStatus.VALIDATED,
                TransactionStatus.REJECTED)
