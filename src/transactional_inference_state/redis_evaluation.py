"""Evaluation-only Redis read/modify/write experiments; not trusted runtime code."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import statistics
import time
from typing import Any

from .redis_participant import (
    BufferedRedisWrite, ExpectedRedisValue, RedisApplyResult, RedisCommitError,
    RedisConflictError, RedisTransactionCoordinator, RedisTransactionalParticipant,
    RedisWriteOperation,
)
from .redis_transport import SocketRedisTransport
from .runtime import PolicyValidator, SessionManager, TransactionManager, TransactionStatus


class CommitFailureTransport:
    """Evaluation injection: reads/preflight work, final outcome is unknown."""
    def __init__(self, delegate: Any) -> None: self.delegate = delegate
    def ping(self): return self.delegate.ping()
    def get(self, key): return self.delegate.get(key)
    def validate(self, expected): return self.delegate.validate(expected)
    def compare_and_apply(self, expected, writes):
        raise OSError("injected ambiguous Redis commit failure")


def _runtime(transport: Any, prefix: str, accept: bool = True):
    sessions = SessionManager(); sessions.create_session("S", user_id="research-user")
    manager = TransactionManager(sessions, validator=PolicyValidator(accept))
    participant = RedisTransactionalParticipant(manager, transport, key_prefix=prefix)
    return sessions, manager, participant, RedisTransactionCoordinator(manager)


def _seed(transport: Any, prefix: str, key: str, value: bytes) -> None:
    _, manager, participant, coordinator = _runtime(transport, prefix)
    tx = coordinator.begin("S", participant); participant.set(tx, "S", key, value)
    manager.validate(tx); coordinator.commit(tx)


def _delete(transport: Any, prefix: str, key: str) -> None:
    _, manager, participant, coordinator = _runtime(transport, prefix)
    tx = coordinator.begin("S", participant); participant.delete(tx, "S", key)
    manager.validate(tx); coordinator.commit(tx)


def _external_value(transport: Any, prefix: str, key: str) -> bytes | None:
    return transport.get((prefix + key).encode())


def _external_set(transport: Any, prefix: str, key: str,
                  before: bytes | None, after: bytes) -> None:
    encoded = (prefix + key).encode()
    expected = {encoded: ExpectedRedisValue(before is not None, before, "evaluation")}
    writes = {encoded: BufferedRedisWrite(RedisWriteOperation.SET, after)}
    result = transport.compare_and_apply(expected, writes)
    if not result.applied: raise RuntimeError("evaluation external writer conflicted")


def evaluate_scenarios(transport: Any, *, prefix: str = "tis-rmw-eval:") -> dict[str, Any]:
    results: dict[str, Any] = {}
    _seed(transport, prefix, "counter", b"10")

    sessions, manager, participant, coordinator = _runtime(transport, prefix)
    tx = coordinator.begin("S", participant); read = participant.get(tx, "S", "counter")
    derived = str(int(read.value) + 1).encode()
    manager.write_private(tx, "S", "session_memory", "derived_counter", derived,
                          provenance_ids=read.provenance_ids)
    participant.set(tx, "S", "counter", derived, provenance_ids=read.provenance_ids)
    before_commit = _external_value(transport, prefix, "counter")
    manager.validate(tx); coordinator.commit(tx)
    provenance = manager.provenance_for_private("S", "session_memory", "derived_counter")
    results["accepted_read_modify_write"] = {
        "read": read.value.decode(), "derived": derived.decode(),
        "external_before_commit": before_commit.decode(),
        "external_after_commit": _external_value(transport, prefix, "counter").decode(),
        "transaction_status": manager.status(tx).value,
        "runtime_provenance": len(provenance) == 1,
        "provenance_source_type": provenance[0].source_type.value,
        "provenance_origin_transaction": provenance[0].origin_transaction,
        "derived_redis_write_source_ids": list(read.provenance_ids),
    }

    _external_set(transport, prefix, "counter", b"11", b"10")
    _, manager, participant, coordinator = _runtime(transport, prefix, False)
    tx = coordinator.begin("S", participant); read = participant.get(tx, "S", "counter")
    participant.set(tx, "S", "counter", str(int(read.value) + 1).encode(),
                    provenance_ids=read.provenance_ids)
    manager.validate(tx); coordinator.rollback(tx)
    results["rejected_read_modify_write"] = {
        "external_after_rollback": _external_value(transport, prefix, "counter").decode(),
        "transaction_status": manager.status(tx).value,
        "buffer_empty": not participant.context(tx).write_set,
    }

    rw_prefix = prefix + "ryw:"
    _seed(transport, rw_prefix, "key", b"A")
    _, manager, participant, coordinator = _runtime(transport, rw_prefix)
    tx = coordinator.begin("S", participant); first = participant.get(tx, "S", "key")
    participant.set(tx, "S", "key", b"B", provenance_ids=first.provenance_ids)
    second = participant.get(tx, "S", "key")
    outside = _external_value(transport, rw_prefix, "key")
    results["read_your_writes"] = {
        "first": first.value.decode(), "second": second.value.decode(),
        "second_from_write_set": second.from_write_set,
        "external_before_commit": outside.decode(),
    }
    manager.validate(tx); coordinator.commit(tx)
    results["read_your_writes"]["external_after_commit"] = _external_value(transport, rw_prefix, "key").decode()

    isolation_prefix = prefix + "isolation:"
    _seed(transport, isolation_prefix, "key", b"A")
    sessions = SessionManager(); sessions.create_session("T1"); sessions.create_session("T2")
    manager = TransactionManager(sessions, validator=PolicyValidator(False))
    participant = RedisTransactionalParticipant(manager, transport, key_prefix=isolation_prefix)
    coordinator = RedisTransactionCoordinator(manager)
    t1 = coordinator.begin("T1", participant); participant.set(t1, "T1", "key", b"B")
    t2 = coordinator.begin("T2", participant); observed = participant.get(t2, "T2", "key")
    results["cross_transaction_isolation"] = {
        "t1_tentative": participant.get(t1, "T1", "key").value.decode(),
        "t2_observed": observed.value.decode(),
        "external_observed": _external_value(transport, isolation_prefix, "key").decode(),
    }
    manager.validate(t1); manager.validate(t2); coordinator.rollback(t1); coordinator.rollback(t2)

    conflict_prefix = prefix + "conflict:"
    _seed(transport, conflict_prefix, "key", b"A")
    sessions, manager, participant, coordinator = _runtime(transport, conflict_prefix)
    tx = coordinator.begin("S", participant); participant.get(tx, "S", "key")
    participant.set(tx, "S", "key", b"B")
    _external_set(transport, conflict_prefix, "key", b"A", b"C")
    manager.validate(tx); conflict = False
    try: coordinator.commit(tx)
    except RedisConflictError: conflict = True
    results["external_conflict"] = {
        "conflict_detected": conflict,
        "external_after_attempt": _external_value(transport, conflict_prefix, "key").decode(),
        "transaction_status": manager.status(tx).value,
    }

    failure_prefix = prefix + "failure:"
    _seed(transport, failure_prefix, "key", b"A")
    failing = CommitFailureTransport(transport)
    sessions, manager, participant, coordinator = _runtime(failing, failure_prefix)
    tx = coordinator.begin("S", participant); participant.set(tx, "S", "key", b"B")
    manager.write_private(tx, "S", "session_memory", "local", "committed")
    manager.validate(tx); failed = False
    try: coordinator.commit(tx)
    except RedisCommitError: failed = True
    results["redis_failure_during_commit"] = {
        "failure_observed": failed, "transaction_status": manager.status(tx).value,
        "reported_success": manager.status(tx) is TransactionStatus.COMMITTED,
        "local_state_committed": sessions.get_session("S").session_memory.get("local") == "committed",
        "external_after_attempt": _external_value(transport, failure_prefix, "key").decode(),
        "external_outcome_classification": "UNKNOWN",
    }

    for cleanup_prefix in (prefix, rw_prefix, isolation_prefix, conflict_prefix, failure_prefix):
        _delete(transport, cleanup_prefix, "counter" if cleanup_prefix == prefix else "key")
    return results


def benchmark(transport: Any, *, prefix: str = "tis-rmw-bench:", iterations: int = 30) -> dict[str, Any]:
    _seed(transport, prefix, "counter", b"0")
    samples = {name: [] for name in ("read_ns", "buffered_write_ns", "commit_ns", "rollback_ns", "conflict_abort_ns")}
    for index in range(iterations):
        sessions, manager, participant, coordinator = _runtime(transport, prefix, index % 2 == 0)
        tx = coordinator.begin("S", participant)
        start = time.perf_counter_ns(); read = participant.get(tx, "S", "counter"); samples["read_ns"].append(time.perf_counter_ns()-start)
        start = time.perf_counter_ns(); participant.set(tx, "S", "counter", str(int(read.value)+1).encode(), provenance_ids=read.provenance_ids); samples["buffered_write_ns"].append(time.perf_counter_ns()-start)
        manager.validate(tx); start = time.perf_counter_ns()
        if index % 2 == 0:
            coordinator.commit(tx); samples["commit_ns"].append(time.perf_counter_ns()-start)
        else:
            coordinator.rollback(tx); samples["rollback_ns"].append(time.perf_counter_ns()-start)
    _seed(transport, prefix, "conflict", b"A")
    for _ in range(iterations):
        _, manager, participant, coordinator = _runtime(transport, prefix)
        tx=coordinator.begin("S",participant);participant.get(tx,"S","conflict");participant.set(tx,"S","conflict",b"B")
        _external_set(transport,prefix,"conflict",b"A",b"C");manager.validate(tx);start=time.perf_counter_ns()
        try:coordinator.commit(tx)
        except RedisConflictError:pass
        samples["conflict_abort_ns"].append(time.perf_counter_ns()-start)
        _external_set(transport,prefix,"conflict",b"C",b"A")
    _delete(transport, prefix, "counter");_delete(transport,prefix,"conflict")
    return {name: _summary(values) for name, values in samples.items()}


def benchmark_inference_state(*, iterations: int = 30) -> dict[str, Any]:
    samples = {name: [] for name in ("read_ns", "write_ns", "commit_ns", "rollback_ns")}
    for index in range(iterations):
        sessions = SessionManager(); state = sessions.create_session("S"); state.session_memory["counter"] = 10
        manager = TransactionManager(sessions, validator=PolicyValidator(index % 2 == 0)); tx = manager.begin("S")
        start=time.perf_counter_ns(); value=manager.read_private(tx,"S","session_memory","counter"); samples["read_ns"].append(time.perf_counter_ns()-start)
        start=time.perf_counter_ns(); manager.write_private(tx,"S","session_memory","counter",value+1); samples["write_ns"].append(time.perf_counter_ns()-start)
        manager.validate(tx); start=time.perf_counter_ns()
        if index%2==0: manager.commit(tx); samples["commit_ns"].append(time.perf_counter_ns()-start)
        else: manager.rollback(tx); samples["rollback_ns"].append(time.perf_counter_ns()-start)
    return {name:_summary(values) for name,values in samples.items()}


def _summary(values: list[int]) -> dict[str, float]:
    ordered=sorted(values); return {"samples":len(values),"median_ns":statistics.median(values),"p95_ns":ordered[max(0,int(.95*len(ordered))-1)]}


def generate(destination: str | Path, *, port: int = 6379, iterations: int = 30) -> dict[str, Any]:
    destination=Path(destination); destination.mkdir(parents=True,exist_ok=True)
    transport=SocketRedisTransport(port=port,database=15)
    scenarios=evaluate_scenarios(transport); redis_perf=benchmark(transport,iterations=iterations); local_perf=benchmark_inference_state(iterations=iterations)
    criu_path=Path("evaluation_results/stage15b/native_results.json")
    criu=json.loads(criu_path.read_text())["performance"]["external_tool"] if criu_path.exists() else {"status":"UNAVAILABLE"}
    comparison={"inference_state":{"mechanism":"application-level copy/overlay","performance":local_perf},"redis":{"mechanism":"API read set + buffered write set + compare-and-apply","performance":redis_perf},"criu":{"mechanism":"external process checkpoint/restore","prior_measured_performance":criu},"claims":{"distributed_transaction":False,"redis_copied_into_inference_state":False,"arbitrary_service_support":False}}
    for name,value in (("scenarios.json",scenarios),("performance.json",{"redis":redis_perf,"inference_state":local_perf}),("comparison.json",comparison)):(destination/name).write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
    summary={"scenarios":scenarios,"performance":{"redis":redis_perf,"inference_state":local_perf},"comparison":comparison,"environment":{"redis":"localhost Redis via RESP2","database":15,"iterations":iterations}}
    (destination/"summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    return summary
