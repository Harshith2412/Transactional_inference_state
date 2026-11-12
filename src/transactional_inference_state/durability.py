"""Small append-only transaction journal and deterministic crash recovery.

This module is intentionally a local durability projection, not a database or a
distributed transaction protocol.  Records before ``STATE_COMMITTED`` describe
tentative work; recovery publishes them only after that boundary.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Iterable


JOURNAL_FORMAT_VERSION = 1
GENESIS_HASH = "0" * 64


class JournalError(RuntimeError):
    """Base class for journal validation failures."""


class JournalCorruptionError(JournalError):
    """A complete historical record failed parsing or hash verification."""


class UnsupportedJournalVersion(JournalError):
    """A record uses a schema this runtime cannot safely interpret."""


class SimulatedCrash(RuntimeError):
    """Abrupt experimental interruption; callers must create a new runtime."""


class JournalRecordType(str, Enum):
    TX_BEGIN = "TX_BEGIN"
    STATE_MUTATION = "STATE_MUTATION"
    PROVENANCE_MUTATION = "PROVENANCE_MUTATION"
    LINEAGE_NODE = "LINEAGE_NODE"
    LINEAGE_EDGE = "LINEAGE_EDGE"
    EFFECT_STAGED = "EFFECT_STAGED"
    EFFECT_ATTEMPT = "EFFECT_ATTEMPT"
    VALIDATION_DECISION = "VALIDATION_DECISION"
    PREPARE_COMMIT = "PREPARE_COMMIT"
    STATE_COMMITTED = "STATE_COMMITTED"
    EFFECT_EXECUTED = "EFFECT_EXECUTED"
    EFFECT_FAILED = "EFFECT_FAILED"
    EFFECT_OUTCOME_UNKNOWN = "EFFECT_OUTCOME_UNKNOWN"
    QUARANTINE_WRITE = "QUARANTINE_WRITE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REVIEW_RESOLVED = "REVIEW_RESOLVED"
    INVALIDATION = "INVALIDATION"
    TX_ROLLED_BACK = "TX_ROLLED_BACK"
    TX_COMPLETE = "TX_COMPLETE"
    EXTERNAL_CHECKPOINT = "EXTERNAL_CHECKPOINT"
    EXTERNAL_RESTORE_ATTEMPT = "EXTERNAL_RESTORE_ATTEMPT"
    EXTERNAL_RESTORE_SUCCESS = "EXTERNAL_RESTORE_SUCCESS"
    EXTERNAL_RESTORE_FAILURE = "EXTERNAL_RESTORE_FAILURE"
    EXTERNAL_CHECKPOINT_RELEASE = "EXTERNAL_CHECKPOINT_RELEASE"


class RecoveryClassification(str, Enum):
    INCOMPLETE_UNCOMMITTED = "INCOMPLETE_UNCOMMITTED"
    PREPARED = "PREPARED"
    STATE_COMMITTED_EFFECTS_PENDING = "STATE_COMMITTED_EFFECTS_PENDING"
    PARTIAL_EFFECT_EXECUTION = "PARTIAL_EFFECT_EXECUTION"
    ROLLED_BACK = "ROLLED_BACK"
    COMPLETE = "COMPLETE"
    CORRUPTED = "CORRUPTED"
    EXTERNAL_ROLLBACK_INCOMPLETE = "EXTERNAL_ROLLBACK_INCOMPLETE"
    EXTERNAL_RESTORE_VERIFICATION_REQUIRED = "EXTERNAL_RESTORE_VERIFICATION_REQUIRED"


class CrashPoint(str, Enum):
    AFTER_TX_BEGIN = "AFTER_TX_BEGIN"
    AFTER_FIRST_MUTATION = "AFTER_FIRST_MUTATION"
    AFTER_PROVENANCE_WRITE = "AFTER_PROVENANCE_WRITE"
    AFTER_LINEAGE_WRITE = "AFTER_LINEAGE_WRITE"
    AFTER_VALIDATION = "AFTER_VALIDATION"
    AFTER_PREPARE_COMMIT = "AFTER_PREPARE_COMMIT"
    DURING_STATE_COMMIT = "DURING_STATE_COMMIT"
    AFTER_STATE_COMMIT = "AFTER_STATE_COMMIT"
    BEFORE_FIRST_EFFECT = "BEFORE_FIRST_EFFECT"
    AFTER_FIRST_EFFECT = "AFTER_FIRST_EFFECT"
    DURING_SECOND_EFFECT = "DURING_SECOND_EFFECT"
    AFTER_QUARANTINE_WRITE = "AFTER_QUARANTINE_WRITE"
    BEFORE_TX_COMPLETE = "BEFORE_TX_COMPLETE"


def canonical_json(value: Any) -> str:
    """Return the exact UTF-8 JSON representation covered by record hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


@dataclass(frozen=True)
class JournalRecord:
    journal_format_version: int
    sequence_number: int
    transaction_id: str
    session_id: str
    record_type: JournalRecordType
    payload: dict[str, Any]
    previous_hash: str
    record_hash: str

    def canonical_body(self) -> dict[str, Any]:
        return {
            "journal_format_version": self.journal_format_version,
            "payload": self.payload,
            "record_type": self.record_type.value,
            "sequence_number": self.sequence_number,
            "session_id": self.session_id,
            "transaction_id": self.transaction_id,
        }

    def as_dict(self) -> dict[str, Any]:
        return {**self.canonical_body(), "previous_hash": self.previous_hash,
                "record_hash": self.record_hash}


class TransactionJournal:
    """Newline-delimited canonical JSON with a deterministic SHA-256 chain."""

    def __init__(self, path: str | Path, *, fsync: bool = True,
                 truncate_incomplete_tail: bool = True) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self.fsync = fsync
        self.truncated_tail_bytes = 0
        records = self.read_records(truncate_incomplete_tail=truncate_incomplete_tail)
        self._next_sequence = len(records) + 1
        self._last_hash = records[-1].record_hash if records else GENESIS_HASH

    @staticmethod
    def record_hash(previous_hash: str, body: dict[str, Any]) -> str:
        material = (previous_hash + canonical_json(body)).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def append(self, record_type: JournalRecordType, transaction_id: str,
               session_id: str, payload: dict[str, Any] | None = None,
               *, durable: bool | None = None) -> JournalRecord:
        if not transaction_id or not session_id:
            raise ValueError("transaction_id and session_id must be non-empty")
        body = {
            "journal_format_version": JOURNAL_FORMAT_VERSION,
            "payload": deepcopy(payload or {}),
            "record_type": record_type.value,
            "sequence_number": self._next_sequence,
            "session_id": session_id,
            "transaction_id": transaction_id,
        }
        digest = self.record_hash(self._last_hash, body)
        record = JournalRecord(
            JOURNAL_FORMAT_VERSION, self._next_sequence, transaction_id,
            session_id, record_type, body["payload"], self._last_hash, digest,
        )
        encoded = (canonical_json(record.as_dict()) + "\n").encode("utf-8")
        with self.path.open("ab") as stream:
            stream.write(encoded)
            stream.flush()
            if self.fsync if durable is None else durable:
                os.fsync(stream.fileno())
        self._next_sequence += 1
        self._last_hash = digest
        return record

    def read_records(self, *, truncate_incomplete_tail: bool = False) -> list[JournalRecord]:
        data = self.path.read_bytes() if self.path.exists() else b""
        if not data:
            return []
        parts = data.splitlines(keepends=True)
        complete_size = 0
        records: list[JournalRecord] = []
        previous = GENESIS_HASH
        expected_sequence = 1
        for index, raw in enumerate(parts):
            is_last = index == len(parts) - 1
            if not raw.endswith(b"\n"):
                if is_last and truncate_incomplete_tail:
                    self.truncated_tail_bytes = len(raw)
                    with self.path.open("r+b") as stream:
                        stream.truncate(complete_size)
                        stream.flush()
                        if self.fsync:
                            os.fsync(stream.fileno())
                    break
                raise JournalCorruptionError("incomplete journal tail")
            try:
                item = json.loads(raw)
                version = item["journal_format_version"]
                if version != JOURNAL_FORMAT_VERSION:
                    raise UnsupportedJournalVersion(
                        f"unsupported journal format version: {version}"
                    )
                record_type = JournalRecordType(item["record_type"])
                body = {key: item[key] for key in (
                    "journal_format_version", "payload", "record_type",
                    "sequence_number", "session_id", "transaction_id",
                )}
                expected_hash = self.record_hash(previous, body)
                if (item["sequence_number"] != expected_sequence
                        or item["previous_hash"] != previous
                        or item["record_hash"] != expected_hash):
                    raise JournalCorruptionError(
                        f"JOURNAL_CORRUPTION at record {expected_sequence}"
                    )
                record = JournalRecord(
                    version, item["sequence_number"], item["transaction_id"],
                    item["session_id"], record_type, item["payload"],
                    item["previous_hash"], item["record_hash"],
                )
            except UnsupportedJournalVersion:
                raise
            except JournalCorruptionError:
                raise
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise JournalCorruptionError(
                    f"JOURNAL_CORRUPTION at record {expected_sequence}"
                ) from error
            records.append(record)
            previous = record.record_hash
            expected_sequence += 1
            complete_size += len(raw)
        return records


@dataclass
class RecoveryTransaction:
    transaction_id: str
    session_id: str
    classification: RecoveryClassification
    effects_pending: tuple[str, ...] = ()
    effects_executed: tuple[str, ...] = ()
    effects_unknown: tuple[str, ...] = ()


@dataclass
class RecoveryState:
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    provenance: dict[str, dict[str, Any]] = field(default_factory=dict)
    lineage_nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    lineage_edges: dict[str, dict[str, Any]] = field(default_factory=dict)
    quarantine: dict[str, dict[str, Any]] = field(default_factory=dict)
    reviews: dict[str, dict[str, Any]] = field(default_factory=dict)
    invalidations: dict[str, dict[str, Any]] = field(default_factory=dict)
    executed_idempotency_keys: set[str] = field(default_factory=set)
    transactions: dict[str, RecoveryTransaction] = field(default_factory=dict)
    records_replayed: int = 0
    truncated_tail_bytes: int = 0


class RecoveryManager:
    """Rebuilds committed projections and optionally replays safe fake effects."""

    def __init__(self, journal: TransactionJournal) -> None:
        self.journal = journal

    def recover(self, *, effect_executor: Callable[[dict[str, Any]], None] | None = None,
                effect_lookup: Callable[[str], bool] | None = None) -> RecoveryState:
        records = self.journal.read_records(truncate_incomplete_tail=True)
        grouped: dict[str, list[JournalRecord]] = {}
        for record in records:
            grouped.setdefault(record.transaction_id, []).append(record)
        result = RecoveryState(records_replayed=len(records),
                               truncated_tail_bytes=self.journal.truncated_tail_bytes)
        # First collect receipts globally so repeated recovery and duplicate keys are safe.
        for record in records:
            if record.record_type is JournalRecordType.EFFECT_EXECUTED:
                key = record.payload.get("idempotency_key")
                if key:
                    result.executed_idempotency_keys.add(key)
        for transaction_id, tx_records in grouped.items():
            tx = self._recover_transaction(tx_records, result, effect_executor, effect_lookup)
            result.transactions[transaction_id] = tx
        return result

    def _recover_transaction(
        self, records: list[JournalRecord], state: RecoveryState,
        executor: Callable[[dict[str, Any]], None] | None,
        lookup: Callable[[str], bool] | None,
    ) -> RecoveryTransaction:
        transaction_id, session_id = records[0].transaction_id, records[0].session_id
        types = [record.record_type for record in records]
        if JournalRecordType.TX_COMPLETE in types:
            classification = RecoveryClassification.COMPLETE
        elif JournalRecordType.TX_ROLLED_BACK in types:
            classification = RecoveryClassification.ROLLED_BACK
        elif JournalRecordType.STATE_COMMITTED not in types:
            classification = (RecoveryClassification.PREPARED
                              if JournalRecordType.PREPARE_COMMIT in types
                              else RecoveryClassification.INCOMPLETE_UNCOMMITTED)
        else:
            staged = [r for r in records if r.record_type is JournalRecordType.EFFECT_STAGED]
            executed = {r.payload["effect_id"] for r in records
                        if r.record_type is JournalRecordType.EFFECT_EXECUTED}
            classification = (RecoveryClassification.PARTIAL_EFFECT_EXECUTION
                              if executed and len(executed) < len(staged)
                              else RecoveryClassification.STATE_COMMITTED_EFFECTS_PENDING)
        committed = JournalRecordType.STATE_COMMITTED in types
        if committed:
            self._publish(records, state)
        staged_by_id = {r.payload["effect_id"]: r.payload for r in records
                        if r.record_type is JournalRecordType.EFFECT_STAGED}
        executed_ids = {r.payload["effect_id"] for r in records
                        if r.record_type is JournalRecordType.EFFECT_EXECUTED}
        attempted_ids = {r.payload["effect_id"] for r in records
                         if r.record_type is JournalRecordType.EFFECT_ATTEMPT}
        self._publish_durable_control(records, state)
        unknown, pending = [], []
        if committed:
            for effect_id, effect in staged_by_id.items():
                key = effect["idempotency_key"]
                if effect_id in executed_ids or key in state.executed_idempotency_keys:
                    continue
                if effect_id in attempted_ids:
                    if lookup is not None and lookup(key):
                        state.executed_idempotency_keys.add(key)
                    else:
                        unknown.append(effect_id)
                    continue
                pending.append(effect_id)
                if executor is not None:
                    executor(deepcopy(effect))
                    # Recovery receipt is journaled before returning; repeating recover is safe.
                    self.journal.append(JournalRecordType.EFFECT_EXECUTED,
                                        transaction_id, session_id,
                                        {"effect_id": effect_id, "idempotency_key": key,
                                         "recovered": True})
                    state.executed_idempotency_keys.add(key)
            if pending and executor is not None:
                pending = []
        return RecoveryTransaction(
            transaction_id, session_id, classification, tuple(pending),
            tuple(sorted(executed_ids)), tuple(unknown),
        )

    @staticmethod
    def _publish(records: Iterable[JournalRecord], state: RecoveryState) -> None:
        for record in records:
            payload = record.payload
            if record.record_type is JournalRecordType.STATE_MUTATION:
                target = state.sessions.setdefault(record.session_id, {})
                path = payload["path"]
                if payload.get("operation", "set") == "delete":
                    target.pop(path, None)
                else:
                    target[path] = deepcopy(payload["value"])
            elif record.record_type is JournalRecordType.PROVENANCE_MUTATION:
                state.provenance[payload["provenance_id"]] = deepcopy(payload)
            elif record.record_type is JournalRecordType.LINEAGE_NODE:
                state.lineage_nodes[payload["node_id"]] = deepcopy(payload)
            elif record.record_type is JournalRecordType.LINEAGE_EDGE:
                key = f'{payload["parent_id"]}->{payload["child_id"]}'
                state.lineage_edges[key] = deepcopy(payload)
            elif record.record_type is JournalRecordType.INVALIDATION:
                state.invalidations[payload["invalidation_id"]] = deepcopy(payload)

    @staticmethod
    def _publish_durable_control(records: Iterable[JournalRecord],
                                 state: RecoveryState) -> None:
        """Quarantine/review records are durable control state, never ordinary state."""
        for record in records:
            if record.record_type is JournalRecordType.QUARANTINE_WRITE:
                state.quarantine[record.payload["quarantine_id"]] = deepcopy(record.payload)
            elif record.record_type is JournalRecordType.REVIEW_REQUIRED:
                state.reviews[record.transaction_id] = deepcopy(record.payload)
            elif record.record_type is JournalRecordType.REVIEW_RESOLVED:
                state.reviews.pop(record.transaction_id, None)


class DurableTransactionRuntime:
    """Thin deterministic authoring facade used by crash/restart experiments."""

    def __init__(self, journal: TransactionJournal,
                 crash_point: CrashPoint | None = None) -> None:
        self.journal, self.crash_point = journal, crash_point
        self._mutation_counts: dict[str, int] = {}

    def _append(self, kind: JournalRecordType, tx: str, session: str,
                payload: dict[str, Any] | None = None,
                crash_after: CrashPoint | None = None) -> JournalRecord:
        record = self.journal.append(kind, tx, session, payload)
        if crash_after is not None and crash_after is self.crash_point:
            raise SimulatedCrash(crash_after.value)
        return record

    def begin(self, tx: str, session: str) -> None:
        self._append(JournalRecordType.TX_BEGIN, tx, session,
                     crash_after=CrashPoint.AFTER_TX_BEGIN)

    def mutate(self, tx: str, session: str, path: str, value: Any) -> None:
        count = self._mutation_counts.get(tx, 0) + 1
        self._mutation_counts[tx] = count
        self._append(JournalRecordType.STATE_MUTATION, tx, session,
                     {"path": path, "value": deepcopy(value), "operation": "set"},
                     CrashPoint.AFTER_FIRST_MUTATION if count == 1 else None)

    def provenance(self, tx: str, session: str, **payload: Any) -> None:
        self._append(JournalRecordType.PROVENANCE_MUTATION, tx, session, payload,
                     CrashPoint.AFTER_PROVENANCE_WRITE)

    def lineage_node(self, tx: str, session: str, **payload: Any) -> None:
        self._append(JournalRecordType.LINEAGE_NODE, tx, session, payload)

    def lineage_edge(self, tx: str, session: str, **payload: Any) -> None:
        self._append(JournalRecordType.LINEAGE_EDGE, tx, session, payload,
                     CrashPoint.AFTER_LINEAGE_WRITE)

    def stage_effect(self, tx: str, session: str, *, effect_id: str,
                     idempotency_key: str, operation: str = "send_email",
                     arguments: dict[str, Any] | None = None) -> None:
        self._append(JournalRecordType.EFFECT_STAGED, tx, session, {
            "effect_id": effect_id, "idempotency_key": idempotency_key,
            "operation": operation, "arguments": deepcopy(arguments or {}),
        })

    def validate(self, tx: str, session: str, accepted: bool) -> None:
        self._append(JournalRecordType.VALIDATION_DECISION, tx, session,
                     {"accepted": accepted}, CrashPoint.AFTER_VALIDATION)

    def prepare(self, tx: str, session: str) -> None:
        self._append(JournalRecordType.PREPARE_COMMIT, tx, session, {},
                     CrashPoint.AFTER_PREPARE_COMMIT)

    def commit_state(self, tx: str, session: str) -> None:
        if self.crash_point is CrashPoint.DURING_STATE_COMMIT:
            raise SimulatedCrash(CrashPoint.DURING_STATE_COMMIT.value)
        self._append(JournalRecordType.STATE_COMMITTED, tx, session, {},
                     CrashPoint.AFTER_STATE_COMMIT)

    def execute_effect(self, tx: str, session: str, effect_id: str,
                       idempotency_key: str, executor: Callable[[], None],
                       *, ordinal: int = 1, ambiguous_crash: bool = False) -> None:
        before = CrashPoint.BEFORE_FIRST_EFFECT if ordinal == 1 else None
        if self.crash_point is before:
            raise SimulatedCrash(before.value)
        self._append(JournalRecordType.EFFECT_ATTEMPT, tx, session,
                     {"effect_id": effect_id, "idempotency_key": idempotency_key})
        executor()
        if ambiguous_crash or (ordinal == 2 and self.crash_point is CrashPoint.DURING_SECOND_EFFECT):
            raise SimulatedCrash(CrashPoint.DURING_SECOND_EFFECT.value)
        self._append(JournalRecordType.EFFECT_EXECUTED, tx, session,
                     {"effect_id": effect_id, "idempotency_key": idempotency_key},
                     CrashPoint.AFTER_FIRST_EFFECT if ordinal == 1 else None)

    def quarantine(self, tx: str, session: str, **payload: Any) -> None:
        self._append(JournalRecordType.QUARANTINE_WRITE, tx, session, payload,
                     CrashPoint.AFTER_QUARANTINE_WRITE)

    def review_required(self, tx: str, session: str, token: str,
                        decision: dict[str, Any]) -> None:
        self._append(JournalRecordType.REVIEW_REQUIRED, tx, session,
                     {"review_token": token, "decision": deepcopy(decision)})

    def complete(self, tx: str, session: str) -> None:
        if self.crash_point is CrashPoint.BEFORE_TX_COMPLETE:
            raise SimulatedCrash(CrashPoint.BEFORE_TX_COMPLETE.value)
        self._append(JournalRecordType.TX_COMPLETE, tx, session)

    def rollback(self, tx: str, session: str) -> None:
        self._append(JournalRecordType.TX_ROLLED_BACK, tx, session)
