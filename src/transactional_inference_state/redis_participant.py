"""Narrow API-mediated Redis transaction participant.

Only the trusted participant sees a transport.  Redis values are not part of
InferenceState and writes remain buffered until coordinated commit.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from typing import Mapping, Protocol

from .effects import EffectStatus
from .provenance import RuntimeSourceType, TrustLabel
from .runtime import TransactionError, TransactionManager, TransactionStatus


class RedisParticipantError(TransactionError): pass
class RedisUnavailableError(RedisParticipantError): pass
class RedisConflictError(RedisParticipantError): pass
class RedisCommitError(RedisParticipantError): pass


class RedisWriteOperation(str, Enum):
    SET = "SET"
    DELETE = "DELETE"


class RedisParticipantStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PREPARED = "PREPARED"
    FLUSHED = "FLUSHED"
    DISCARDED = "DISCARDED"
    CONFLICTED = "CONFLICTED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class ExpectedRedisValue:
    exists: bool
    value: bytes | None
    digest: str


@dataclass(frozen=True)
class BufferedRedisWrite:
    operation: RedisWriteOperation
    value: bytes | None = None
    provenance_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class RedisRead:
    key: str
    value: bytes | None
    exists: bool
    observed_digest: str
    provenance_ids: tuple[str, ...]
    from_write_set: bool = False


@dataclass(frozen=True)
class RedisApplyResult:
    applied: bool
    conflict: bool = False


class RedisTransport(Protocol):
    """Trusted transport contract; implementations must compare atomically."""
    def ping(self) -> bool: ...
    def get(self, key: bytes) -> bytes | None: ...
    def validate(self, expected: Mapping[bytes, ExpectedRedisValue]) -> bool: ...
    def compare_and_apply(
        self, expected: Mapping[bytes, ExpectedRedisValue],
        writes: Mapping[bytes, BufferedRedisWrite],
    ) -> RedisApplyResult: ...


@dataclass
class RedisTransactionContext:
    transaction_id: str
    session_id: str
    status: RedisParticipantStatus = RedisParticipantStatus.ACTIVE
    read_set: dict[bytes, ExpectedRedisValue] = field(default_factory=dict)
    read_cache: dict[bytes, bytes | None] = field(default_factory=dict)
    read_provenance: dict[bytes, tuple[str, ...]] = field(default_factory=dict)
    write_set: dict[bytes, BufferedRedisWrite] = field(default_factory=dict)


def _digest(value: bytes | None) -> str:
    marker = b"present\0" + value if value is not None else b"missing\0"
    return hashlib.sha256(marker).hexdigest()


class RedisTransactionalParticipant:
    """Transaction-scoped GET and buffered SET/DELETE over one Redis transport."""
    def __init__(self, manager: TransactionManager, transport: RedisTransport, *,
                 participant_id: str = "redis", key_prefix: str = "tis:",
                 max_key_bytes: int = 256, max_value_bytes: int = 1_048_576,
                 max_operations: int = 128) -> None:
        if not participant_id or not key_prefix:
            raise ValueError("participant_id and key_prefix must be non-empty")
        self.manager = manager
        self._transport = transport
        self.participant_id, self.key_prefix = participant_id, key_prefix
        self.max_key_bytes, self.max_value_bytes = max_key_bytes, max_value_bytes
        self.max_operations = max_operations
        self._contexts: dict[str, RedisTransactionContext] = {}

    def begin(self, transaction_id: str, session_id: str) -> None:
        if transaction_id in self._contexts:
            raise RedisParticipantError("Redis participant already enrolled")
        self.manager.transaction_state(transaction_id, session_id)
        try:
            if not self._transport.ping():
                raise RedisUnavailableError("Redis unavailable at begin")
        except RedisParticipantError:
            raise
        except Exception as error:
            raise RedisUnavailableError("Redis unavailable at begin") from error
        self._contexts[transaction_id] = RedisTransactionContext(transaction_id, session_id)
        self._event("REDIS_PARTICIPANT_ENROLLED", transaction_id, session_id)

    def get(self, transaction_id: str, session_id: str, key: str) -> RedisRead:
        context = self._active(transaction_id, session_id); encoded = self._key(key)
        if encoded in context.write_set:
            write = context.write_set[encoded]
            value = write.value if write.operation is RedisWriteOperation.SET else None
            return RedisRead(key, deepcopy(value), value is not None, _digest(value),
                             write.provenance_ids, True)
        if encoded not in context.read_cache:
            value = self._transport_get(encoded, transaction_id, session_id)
            context.read_cache[encoded] = value
            context.read_set[encoded] = ExpectedRedisValue(
                value is not None, value, _digest(value)
            )
            source = self.manager.issue_provenance(
                transaction_id, RuntimeSourceType.TOOL_RESULT,
                trust_label=TrustLabel.UNKNOWN,
            )
            context.read_provenance[encoded] = (source.source_id,)
        value = context.read_cache[encoded]
        self._event("REDIS_READ", transaction_id, session_id, key_digest=_digest(encoded),
                    exists=value is not None, value_digest=_digest(value))
        return RedisRead(key, deepcopy(value), value is not None, _digest(value),
                         context.read_provenance[encoded])

    def set(self, transaction_id: str, session_id: str, key: str, value: bytes, *,
            provenance_ids: tuple[str, ...] = ()) -> None:
        if not isinstance(value, bytes): raise TypeError("Redis values must be bytes")
        if len(value) > self.max_value_bytes: raise ValueError("Redis value exceeds limit")
        context = self._active(transaction_id, session_id); encoded = self._key(key)
        self._check_budget(context, encoded); self._observe(context, encoded)
        self.manager.validate_provenance_ids(transaction_id, provenance_ids)
        context.write_set[encoded] = BufferedRedisWrite(
            RedisWriteOperation.SET, bytes(value), tuple(provenance_ids)
        )
        self._event("REDIS_WRITE_TENTATIVE", transaction_id, session_id,
                    key_digest=_digest(encoded), value_digest=_digest(value))

    def delete(self, transaction_id: str, session_id: str, key: str, *,
               provenance_ids: tuple[str, ...] = ()) -> None:
        context = self._active(transaction_id, session_id); encoded = self._key(key)
        self._check_budget(context, encoded); self._observe(context, encoded)
        self.manager.validate_provenance_ids(transaction_id, provenance_ids)
        context.write_set[encoded] = BufferedRedisWrite(
            RedisWriteOperation.DELETE, None, tuple(provenance_ids)
        )
        self._event("REDIS_DELETE_TENTATIVE", transaction_id, session_id,
                    key_digest=_digest(encoded))

    def prepare(self, transaction_id: str, session_id: str) -> None:
        context = self._context(transaction_id, session_id)
        if context.status is not RedisParticipantStatus.ACTIVE:
            raise RedisParticipantError("Redis participant is not active")
        try: valid = self._transport.validate(context.read_set)
        except Exception as error:
            context.status = RedisParticipantStatus.FAILED
            raise RedisUnavailableError("Redis unavailable during prepare") from error
        if not valid:
            context.status = RedisParticipantStatus.CONFLICTED
            self._event("REDIS_CONFLICT", transaction_id, session_id, phase="prepare")
            raise RedisConflictError("Redis value changed before commit")
        context.status = RedisParticipantStatus.PREPARED
        self._event("REDIS_PREPARED", transaction_id, session_id)

    def flush(self, transaction_id: str, session_id: str) -> None:
        context = self._context(transaction_id, session_id)
        if context.status is not RedisParticipantStatus.PREPARED:
            raise RedisParticipantError("Redis participant is not prepared")
        try: result = self._transport.compare_and_apply(context.read_set, context.write_set)
        except Exception as error:
            context.status = RedisParticipantStatus.FAILED
            raise RedisCommitError("Redis unavailable during commit") from error
        if not result.applied:
            context.status = RedisParticipantStatus.CONFLICTED
            self._event("REDIS_CONFLICT", transaction_id, session_id, phase="flush")
            raise RedisConflictError("Redis changed during commit window")
        context.status = RedisParticipantStatus.FLUSHED
        write_count = len(context.write_set)
        context.read_set.clear(); context.read_cache.clear()
        context.read_provenance.clear(); context.write_set.clear()
        self._event("REDIS_FLUSHED", transaction_id, session_id,
                    writes=write_count)

    def rollback(self, transaction_id: str, session_id: str) -> None:
        context = self._context(transaction_id, session_id)
        if context.status not in {RedisParticipantStatus.ACTIVE,
                                  RedisParticipantStatus.PREPARED,
                                  RedisParticipantStatus.CONFLICTED,
                                  RedisParticipantStatus.FAILED}:
            raise RedisParticipantError("Redis participant is already closed")
        context.read_set.clear(); context.read_cache.clear()
        context.read_provenance.clear(); context.write_set.clear()
        context.status = RedisParticipantStatus.DISCARDED
        self._event("REDIS_BUFFER_DISCARDED", transaction_id, session_id)

    def context(self, transaction_id: str) -> RedisTransactionContext:
        try: return self._contexts[transaction_id]
        except KeyError as error: raise RedisParticipantError("unknown Redis transaction") from error

    def _observe(self, context: RedisTransactionContext, key: bytes) -> None:
        if key in context.read_set: return
        value = self._transport_get(key, context.transaction_id, context.session_id)
        context.read_cache[key] = value
        context.read_set[key] = ExpectedRedisValue(value is not None, value, _digest(value))

    def _transport_get(self, key: bytes, transaction_id: str, session_id: str) -> bytes | None:
        try: return self._transport.get(key)
        except Exception as error:
            self._event("REDIS_UNAVAILABLE", transaction_id, session_id, phase="read")
            raise RedisUnavailableError("Redis unavailable during read") from error

    def _active(self, transaction_id: str, session_id: str) -> RedisTransactionContext:
        context = self._context(transaction_id, session_id)
        if context.status is not RedisParticipantStatus.ACTIVE:
            raise RedisParticipantError("Redis participant is not active")
        self.manager.transaction_state(transaction_id, session_id)
        return context

    def _context(self, transaction_id: str, session_id: str) -> RedisTransactionContext:
        context = self.context(transaction_id)
        if context.session_id != session_id:
            raise RedisParticipantError("Redis transaction does not belong to session")
        return context

    def _key(self, key: str) -> bytes:
        if not isinstance(key, str) or not key: raise ValueError("Redis key must be non-empty")
        encoded = (self.key_prefix + key).encode("utf-8")
        if len(encoded) > self.max_key_bytes: raise ValueError("Redis key exceeds limit")
        return encoded

    def _check_budget(self, context: RedisTransactionContext, key: bytes) -> None:
        if key not in context.write_set and len(context.write_set) >= self.max_operations:
            raise RedisParticipantError("Redis operation budget exceeded")

    def _event(self, kind: str, transaction_id: str, session_id: str, **details: object) -> None:
        self.manager.event_log.record(kind, transaction_id, session_id=session_id,
                                      participant_id=self.participant_id, **details)


class RedisTransactionCoordinator:
    """Coordinates one Redis participant without claiming cross-system atomicity."""
    def __init__(self, manager: TransactionManager) -> None:
        self.manager = manager
        self._participants: dict[str, RedisTransactionalParticipant] = {}

    def begin(self, session_id: str,
              participant: RedisTransactionalParticipant | None = None) -> str:
        if isinstance(participant, (list, tuple)):
            raise RedisParticipantError("max_redis_participants=1")
        if participant is not None and participant.manager is not self.manager:
            raise RedisParticipantError("Redis participant belongs to another manager")
        transaction_id = self.manager.begin(session_id)
        if participant is None: return transaction_id
        try: participant.begin(transaction_id, session_id)
        except Exception:
            self.manager.rollback(transaction_id); raise
        self._participants[transaction_id] = participant
        return transaction_id

    def commit(self, transaction_id: str) -> None:
        participant = self._participants.get(transaction_id)
        if participant is None:
            self.manager.commit(transaction_id); return
        context = participant.context(transaction_id)
        try: self._reject_mixed_resources(transaction_id, context.session_id)
        except Exception:
            self.manager.rollback(transaction_id)
            participant.rollback(transaction_id, context.session_id)
            raise
        try: participant.prepare(transaction_id, context.session_id)
        except Exception:
            self.manager.rollback(transaction_id)
            if participant.context(transaction_id).status is not RedisParticipantStatus.DISCARDED:
                participant.rollback(transaction_id, context.session_id)
            raise
        try: self.manager.commit(transaction_id)
        except Exception:
            if participant.context(transaction_id).status is RedisParticipantStatus.PREPARED:
                participant.rollback(transaction_id, context.session_id)
            if self.manager.status(transaction_id) in {
                TransactionStatus.ACTIVE, TransactionStatus.VALIDATED,
                TransactionStatus.REJECTED,
            }:
                self.manager.rollback(transaction_id)
            raise
        try: participant.flush(transaction_id, context.session_id)
        except Exception:
            self.manager.mark_partially_committed(transaction_id)
            raise

    def rollback(self, transaction_id: str) -> None:
        participant = self._participants.get(transaction_id)
        self.manager.rollback(transaction_id)
        if participant is not None:
            participant.rollback(transaction_id, participant.context(transaction_id).session_id)

    def participant(self, transaction_id: str) -> RedisTransactionalParticipant:
        try: return self._participants[transaction_id]
        except KeyError as error: raise RedisParticipantError("transaction has no Redis participant") from error

    def _reject_mixed_resources(self, transaction_id: str, session_id: str) -> None:
        if self.manager.write_set(transaction_id):
            raise RedisParticipantError("Redis prototype cannot combine shared-state writes")
        effects = self.manager.effect_manager
        if effects is not None and any(
            item.status is EffectStatus.STAGED
            for item in effects.list_effects(transaction_id, session_id)
        ):
            raise RedisParticipantError("Redis prototype cannot combine executable effects")
