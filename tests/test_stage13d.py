import json

import pytest

import transactional_inference_state as tis


def runtime(tmp_path, crash=None, *, fsync=False):
    journal = tis.TransactionJournal(tmp_path / "journal.jsonl", fsync=fsync)
    return journal, tis.DurableTransactionRuntime(journal, crash)


def committed(runtime, tx="tx-1", session="session-a", *, complete=True):
    runtime.begin(tx, session)
    runtime.mutate(tx, session, "session_memory.authorization", "approved")
    runtime.provenance(tx, session, provenance_id="source-1", origin_user="user-a",
                       origin_session=session, origin_transaction=tx,
                       origin_source="prompt")
    runtime.lineage_node(tx, session, node_id="T1", source_id="source-1")
    runtime.validate(tx, session, True)
    runtime.prepare(tx, session)
    runtime.commit_state(tx, session)
    if complete:
        runtime.complete(tx, session)


def test_canonical_serialization_and_append(tmp_path):
    journal, rt = runtime(tmp_path)
    rt.begin("tx", "s")
    line = (tmp_path / "journal.jsonl").read_text()
    assert line == tis.canonical_json(json.loads(line)) + "\n"
    assert journal.read_records()[0].record_type is tis.JournalRecordType.TX_BEGIN


def test_hash_chain_and_corruption_detection(tmp_path):
    journal, rt = runtime(tmp_path)
    rt.begin("tx", "s"); rt.validate("tx", "s", True)
    records = journal.read_records()
    assert records[1].previous_hash == records[0].record_hash
    path = tmp_path / "journal.jsonl"
    path.write_text(path.read_text().replace('"accepted":true', '"accepted":false'))
    with pytest.raises(tis.JournalCorruptionError, match="JOURNAL_CORRUPTION"):
        tis.TransactionJournal(path, fsync=False)


def test_truncated_tail_is_removed_but_middle_corruption_is_rejected(tmp_path):
    journal, rt = runtime(tmp_path)
    rt.begin("tx", "s"); rt.validate("tx", "s", True)
    path = tmp_path / "journal.jsonl"
    original = path.read_bytes(); path.write_bytes(original + b'{"partial":')
    reopened = tis.TransactionJournal(path, fsync=False)
    assert len(reopened.read_records()) == 2
    assert reopened.truncated_tail_bytes == len(b'{"partial":')
    lines = path.read_text().splitlines(True)
    path.write_text(lines[0] + "{}\n" + lines[1])
    with pytest.raises(tis.JournalCorruptionError):
        tis.TransactionJournal(path, fsync=False)


@pytest.mark.parametrize("point,expected", [
    (tis.CrashPoint.AFTER_TX_BEGIN, tis.RecoveryClassification.INCOMPLETE_UNCOMMITTED),
    (tis.CrashPoint.AFTER_FIRST_MUTATION, tis.RecoveryClassification.INCOMPLETE_UNCOMMITTED),
    (tis.CrashPoint.AFTER_PROVENANCE_WRITE, tis.RecoveryClassification.INCOMPLETE_UNCOMMITTED),
    (tis.CrashPoint.AFTER_VALIDATION, tis.RecoveryClassification.INCOMPLETE_UNCOMMITTED),
    (tis.CrashPoint.AFTER_PREPARE_COMMIT, tis.RecoveryClassification.PREPARED),
    (tis.CrashPoint.DURING_STATE_COMMIT, tis.RecoveryClassification.PREPARED),
    (tis.CrashPoint.AFTER_STATE_COMMIT, tis.RecoveryClassification.STATE_COMMITTED_EFFECTS_PENDING),
    (tis.CrashPoint.BEFORE_TX_COMPLETE, tis.RecoveryClassification.STATE_COMMITTED_EFFECTS_PENDING),
])
def test_crash_boundaries(tmp_path, point, expected):
    journal, rt = runtime(tmp_path, point)
    with pytest.raises(tis.SimulatedCrash):
        committed(rt)
    recovered = tis.RecoveryManager(tis.TransactionJournal(journal.path, fsync=False)).recover()
    assert recovered.transactions["tx-1"].classification is expected
    visible = recovered.sessions.get("session-a", {})
    if point in {tis.CrashPoint.AFTER_STATE_COMMIT, tis.CrashPoint.BEFORE_TX_COMPLETE}:
        assert visible["session_memory.authorization"] == "approved"
        assert recovered.provenance["source-1"]["origin_user"] == "user-a"
    else:
        assert visible == {} and recovered.provenance == {}


def test_lineage_crash_boundary_discards_tentative_graph(tmp_path):
    journal, rt = runtime(tmp_path, tis.CrashPoint.AFTER_LINEAGE_WRITE)
    with pytest.raises(tis.SimulatedCrash):
        rt.begin("tx", "s"); rt.lineage_node("tx", "s", node_id="T1"); rt.lineage_edge(
            "tx", "s", parent_id="T1", child_id="T3")
    recovered = tis.RecoveryManager(journal).recover()
    assert recovered.lineage_nodes == {} and recovered.lineage_edges == {}


def test_pending_effect_replays_once_across_repeated_recovery(tmp_path):
    journal, rt = runtime(tmp_path)
    rt.begin("tx", "s"); rt.stage_effect("tx", "s", effect_id="e1",
        idempotency_key="mail-1", arguments={"to": "a@example.test"})
    rt.validate("tx", "s", True); rt.prepare("tx", "s"); rt.commit_state("tx", "s")
    calls = []
    manager = tis.RecoveryManager(journal)
    manager.recover(effect_executor=lambda effect: calls.append(effect["idempotency_key"]))
    manager.recover(effect_executor=lambda effect: calls.append(effect["idempotency_key"]))
    assert calls == ["mail-1"]


def test_effect_receipt_suppresses_duplicate_after_crash(tmp_path):
    journal, rt = runtime(tmp_path, tis.CrashPoint.AFTER_FIRST_EFFECT)
    calls = []
    rt.begin("tx", "s"); rt.stage_effect("tx", "s", effect_id="e1", idempotency_key="k1")
    rt.validate("tx", "s", True); rt.prepare("tx", "s"); rt.commit_state("tx", "s")
    with pytest.raises(tis.SimulatedCrash):
        rt.execute_effect("tx", "s", "e1", "k1", lambda: calls.append("sent"))
    tis.RecoveryManager(journal).recover(effect_executor=lambda _: calls.append("duplicate"))
    assert calls == ["sent"]


def test_ambiguous_effect_is_reported_not_replayed(tmp_path):
    journal, rt = runtime(tmp_path)
    calls = []
    rt.begin("tx", "s"); rt.stage_effect("tx", "s", effect_id="e1", idempotency_key="k1")
    rt.validate("tx", "s", True); rt.prepare("tx", "s"); rt.commit_state("tx", "s")
    with pytest.raises(tis.SimulatedCrash):
        rt.execute_effect("tx", "s", "e1", "k1", lambda: calls.append("sent"),
                          ambiguous_crash=True)
    recovered = tis.RecoveryManager(journal).recover(
        effect_executor=lambda _: calls.append("duplicate"))
    assert calls == ["sent"]
    assert recovered.transactions["tx"].effects_unknown == ("e1",)


def test_quarantine_and_review_survive_without_ordinary_visibility(tmp_path):
    journal, rt = runtime(tmp_path)
    rt.begin("tx-q", "s"); rt.quarantine("tx-q", "s", quarantine_id="q1",
        path="memory.B", value="unsafe", lineage_ids=["T1"])
    rt.begin("tx-r", "s"); rt.review_required("tx-r", "s", "token-1", {"action": "review"})
    recovered = tis.RecoveryManager(journal).recover()
    assert recovered.sessions == {}
    assert recovered.quarantine["q1"]["value"] == "unsafe"
    assert recovered.reviews["tx-r"]["review_token"] == "token-1"


def test_selective_commit_and_restart_lineage(tmp_path):
    journal, rt = runtime(tmp_path)
    rt.begin("tx", "s"); rt.mutate("tx", "s", "memory.A", "safe")
    for node in ("T1", "T3", "T5"):
        rt.lineage_node("tx", "s", node_id=node)
    rt.lineage_edge("tx", "s", parent_id="T1", child_id="T3")
    rt.lineage_edge("tx", "s", parent_id="T3", child_id="T5")
    rt.quarantine("tx", "s", quarantine_id="qB", path="memory.B", value="unsafe")
    rt.quarantine("tx", "s", quarantine_id="qC", path="memory.C", value="dependent")
    rt.validate("tx", "s", True); rt.prepare("tx", "s"); rt.commit_state("tx", "s"); rt.complete("tx", "s")
    first = tis.RecoveryManager(journal).recover()
    rt2 = tis.DurableTransactionRuntime(tis.TransactionJournal(journal.path, fsync=False))
    rt2.begin("tx2", "s"); rt2.lineage_node("tx2", "s", node_id="T7")
    rt2.lineage_node("tx2", "s", node_id="T8"); rt2.lineage_edge("tx2", "s", parent_id="T5", child_id="T7")
    rt2.lineage_edge("tx2", "s", parent_id="T7", child_id="T8")
    rt2.validate("tx2", "s", True); rt2.prepare("tx2", "s"); rt2.commit_state("tx2", "s"); rt2.complete("tx2", "s")
    second = tis.RecoveryManager(journal).recover()
    assert first.sessions["s"] == {"memory.A": "safe"}
    assert set(first.quarantine) == {"qB", "qC"}
    assert "T1->T3" in second.lineage_edges and "T7->T8" in second.lineage_edges


def test_unsupported_version_rejected(tmp_path):
    path = tmp_path / "journal.jsonl"
    item = {"journal_format_version": 99, "sequence_number": 1,
            "transaction_id": "tx", "session_id": "s", "record_type": "TX_BEGIN",
            "payload": {}, "previous_hash": "0" * 64, "record_hash": "x" * 64}
    path.write_text(json.dumps(item) + "\n")
    with pytest.raises(tis.UnsupportedJournalVersion):
        tis.TransactionJournal(path, fsync=False)


def test_policy_and_validator_fingerprints_remain_frozen():
    assert tis.policy_fingerprint(tis.PolicyV1()) == "b9c476b30befcd7ae7a34c0effaee6f991cc84d76d64154d56ee95aba460ffb7"
    assert tis.policy_fingerprint(tis.PolicyV2()) == "ca3702e69066389a46b785e067ad068d34a6401828d0dfc933523216a386962e"
    assert tis.validator_fingerprints() == {
        "POLICY_V2_BASELINE": "994d02bfda279874b751434fd96840c97c06699df60bc98022c7950afa6801c1",
        "SEQUENCE_AWARE": "e2dd7bbdc0fe56b5daf12ee18e1c10c21940d80592173715739793e24bf6e413",
        "PROVENANCE_AWARE": "2098e3b676d8032733e7def21ab4c1ae268bd8999257b24c16f3f1c9f7d3f318",
        "SEMANTIC_RULE": "3623808590f95dfbc16245ea29842fc69a6dd0e5e494a88c72cff51df617f82c",
        "HYBRID_DETERMINISTIC": "13cba36c7f4b004fbe6f414784777984bd82f5ba1aa6f614bebc40350856ec9c",
    }


def test_complete_crash_matrix_has_every_required_boundary(tmp_path):
    rows = tis.run_crash_matrix(tmp_path / "matrix")
    assert {row["crash_point"] for row in rows} == {point.value for point in tis.CrashPoint}
    before = {tis.CrashPoint.AFTER_TX_BEGIN.value, tis.CrashPoint.AFTER_FIRST_MUTATION.value,
              tis.CrashPoint.AFTER_PROVENANCE_WRITE.value, tis.CrashPoint.AFTER_LINEAGE_WRITE.value,
              tis.CrashPoint.AFTER_VALIDATION.value, tis.CrashPoint.AFTER_PREPARE_COMMIT.value,
              tis.CrashPoint.DURING_STATE_COMMIT.value, tis.CrashPoint.AFTER_QUARANTINE_WRITE.value}
    assert all(not row["state"] for row in rows if row["crash_point"] in before)
    assert all(row["state"] for row in rows if row["crash_point"] not in before)
