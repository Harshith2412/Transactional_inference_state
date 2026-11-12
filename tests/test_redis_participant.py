from __future__ import annotations
from threading import RLock
import pytest
import transactional_inference_state as tis


class InMemoryRedisTransport:
    def __init__(self, initial=None):
        self.values = {k.encode(): bytes(v) for k, v in (initial or {}).items()}
        self.available = True; self.fail_apply = False; self.change_during_apply = None
        self.get_calls = 0; self.apply_calls = 0; self._lock = RLock()
    def ping(self):
        if not self.available: raise OSError("offline")
        return True
    def get(self, key):
        if not self.available: raise OSError("offline")
        self.get_calls += 1; return self.values.get(key)
    def validate(self, expected):
        if not self.available: raise OSError("offline")
        return self._matches(expected)
    def compare_and_apply(self, expected, writes):
        with self._lock:
            self.apply_calls += 1
            if self.fail_apply: raise OSError("offline during apply")
            if self.change_during_apply:
                key, value = self.change_during_apply; self.values[key.encode()] = value
            if not self._matches(expected): return tis.RedisApplyResult(False, True)
            for key, write in writes.items():
                if write.operation is tis.RedisWriteOperation.SET: self.values[key] = write.value
                else: self.values.pop(key, None)
            return tis.RedisApplyResult(True)
    def _matches(self, expected):
        return all((key in self.values) == item.exists and self.values.get(key) == item.value
                   for key, item in expected.items())


def runtime(initial=None, accepted=True, **participant_options):
    sessions = tis.SessionManager(); sessions.create_session("A", user_id="user-a"); sessions.create_session("B", user_id="user-b")
    manager = tis.TransactionManager(sessions, validator=tis.PolicyValidator(accepted))
    transport = InMemoryRedisTransport(initial)
    participant = tis.RedisTransactionalParticipant(manager, transport, **participant_options)
    return sessions, manager, transport, participant, tis.RedisTransactionCoordinator(manager)


def test_set_is_buffered_read_your_writes_and_commit_flushes():
    _, manager, transport, participant, coordinator = runtime({"tis:role": b"user"})
    tx = coordinator.begin("A", participant); participant.set(tx, "A", "role", b"admin")
    assert transport.values[b"tis:role"] == b"user"
    read = participant.get(tx, "A", "role")
    assert read.value == b"admin" and read.from_write_set
    manager.validate(tx); coordinator.commit(tx)
    assert transport.values[b"tis:role"] == b"admin"
    assert manager.status(tx) is tis.TransactionStatus.COMMITTED


def test_delete_is_buffered_and_rollback_drops_buffer():
    _, manager, transport, participant, coordinator = runtime({"tis:key": b"value"}, False)
    tx = coordinator.begin("A", participant); participant.delete(tx, "A", "key")
    assert participant.get(tx, "A", "key").exists is False
    assert transport.values[b"tis:key"] == b"value"
    manager.validate(tx); coordinator.rollback(tx)
    assert transport.values[b"tis:key"] == b"value"
    assert participant.context(tx).write_set == {}
    assert participant.context(tx).status is tis.RedisParticipantStatus.DISCARDED


def test_delete_flushes_on_accepted_commit():
    _, manager, transport, participant, coordinator = runtime({"tis:key": b"value"})
    tx = coordinator.begin("A", participant); participant.delete(tx, "A", "key")
    manager.validate(tx); coordinator.commit(tx)
    assert b"tis:key" not in transport.values


def test_uncommitted_write_is_invisible_to_other_transaction():
    _, manager, transport, participant, coordinator = runtime({"tis:role": b"user"}, False)
    a = coordinator.begin("A", participant); b = coordinator.begin("B", participant)
    participant.set(a, "A", "role", b"admin")
    assert participant.get(a, "A", "role").value == b"admin"
    assert participant.get(b, "B", "role").value == b"user"
    assert transport.values[b"tis:role"] == b"user"
    manager.validate(a); manager.validate(b); coordinator.rollback(a); coordinator.rollback(b)


def test_get_provenance_can_label_tentative_derived_state_and_is_discarded():
    sessions, manager, _, participant, coordinator = runtime({"tis:project": b"atlas"}, False)
    tx = coordinator.begin("A", participant); read = participant.get(tx, "A", "project")
    record = manager.provenance_registry.get(read.provenance_ids[0])
    assert record.source_type is tis.RuntimeSourceType.TOOL_RESULT
    assert record.origin_transaction == tx and record.origin_session == "A" and not record.committed
    manager.write_private(tx, "A", "session_memory", "project", read.value,
                          provenance_ids=read.provenance_ids)
    participant.set(tx, "A", "derived", b"atlas-cache",
                    provenance_ids=read.provenance_ids)
    assert participant.context(tx).write_set[b"tis:derived"].provenance_ids == read.provenance_ids
    assert sessions.get_session("A").session_memory == {}
    manager.validate(tx); coordinator.rollback(tx)
    assert sessions.get_session("A").session_memory == {}
    assert not manager.provenance_registry.contains(record.source_id)


def test_model_provided_or_forged_provenance_is_rejected():
    _, _, _, participant, coordinator = runtime()
    tx = coordinator.begin("A", participant)
    with pytest.raises(tis.TransactionError, match="issued by the runtime"):
        participant.set(tx, "A", "x", b"value", provenance_ids=("model-claimed",))


def test_stale_observation_conflicts_before_local_commit():
    sessions, manager, transport, participant, coordinator = runtime({"tis:role": b"user"})
    tx = coordinator.begin("A", participant); participant.get(tx, "A", "role")
    participant.set(tx, "A", "role", b"admin")
    manager.write_private(tx, "A", "session_memory", "decision", "tentative")
    transport.values[b"tis:role"] = b"moderator"
    manager.validate(tx)
    with pytest.raises(tis.RedisConflictError): coordinator.commit(tx)
    assert manager.status(tx) is tis.TransactionStatus.ROLLED_BACK
    assert sessions.get_session("A").session_memory == {}
    assert transport.values[b"tis:role"] == b"moderator" and transport.apply_calls == 0


def test_race_during_atomic_flush_is_explicit_partial_commit():
    sessions, manager, transport, participant, coordinator = runtime({"tis:role": b"user"})
    tx = coordinator.begin("A", participant); participant.set(tx, "A", "role", b"admin")
    manager.write_private(tx, "A", "session_memory", "local", "committed")
    transport.change_during_apply = ("tis:role", b"moderator")
    manager.validate(tx)
    with pytest.raises(tis.RedisConflictError): coordinator.commit(tx)
    assert manager.status(tx) is tis.TransactionStatus.PARTIALLY_COMMITTED
    assert sessions.get_session("A").session_memory["local"] == "committed"
    assert transport.values[b"tis:role"] == b"moderator"


def test_unavailable_at_begin_rolls_back_local_transaction():
    _, manager, transport, participant, coordinator = runtime(); transport.available = False
    with pytest.raises(tis.RedisUnavailableError, match="begin"): coordinator.begin("A", participant)
    tx = manager.event_log.events[0].transaction_id
    assert manager.status(tx) is tis.TransactionStatus.ROLLED_BACK


def test_unavailable_read_and_commit_are_explicit():
    _, manager, transport, participant, coordinator = runtime({"tis:x": b"old"})
    tx = coordinator.begin("A", participant); transport.available = False
    with pytest.raises(tis.RedisUnavailableError, match="read"): participant.get(tx, "A", "x")
    transport.available = True; participant.set(tx, "A", "x", b"new"); manager.validate(tx)
    transport.fail_apply = True
    with pytest.raises(tis.RedisCommitError): coordinator.commit(tx)
    assert manager.status(tx) is tis.TransactionStatus.PARTIALLY_COMMITTED
    assert transport.values[b"tis:x"] == b"old"


def test_scope_ownership_lifecycle_limits_and_single_participant():
    _, manager, _, participant, coordinator = runtime(max_key_bytes=8, max_value_bytes=3,
                                                       max_operations=1)
    tx = coordinator.begin("A", participant)
    with pytest.raises(tis.RedisParticipantError, match="belong"): participant.get(tx, "B", "x")
    with pytest.raises(ValueError, match="key"): participant.get(tx, "A", "long-key")
    with pytest.raises(ValueError, match="value"): participant.set(tx, "A", "x", b"four")
    manager.validate(tx); coordinator.commit(tx)
    with pytest.raises(tis.RedisParticipantError): participant.get(tx, "A", "x")
    _, _, _, other, _ = runtime()
    with pytest.raises(tis.RedisParticipantError, match="max_redis"):
        coordinator.begin("A", [other, other])


def test_redis_cannot_mix_shared_writes_or_staged_effects():
    _, manager, _, participant, coordinator = runtime()
    tx = coordinator.begin("A", participant); manager.write_shared(tx, "x", 1); manager.validate(tx)
    with pytest.raises(tis.RedisParticipantError, match="shared-state"): coordinator.commit(tx)
    assert manager.status(tx) is tis.TransactionStatus.ROLLED_BACK
    assert participant.context(tx).status is tis.RedisParticipantStatus.DISCARDED


def test_policy_fingerprints_remain_frozen():
    assert tis.policy_fingerprint(tis.PolicyV1()) == "b9c476b30befcd7ae7a34c0effaee6f991cc84d76d64154d56ee95aba460ffb7"
    assert tis.policy_fingerprint(tis.PolicyV2()) == "ca3702e69066389a46b785e067ad068d34a6401828d0dfc933523216a386962e"
