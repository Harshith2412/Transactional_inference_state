"""Opt-in native CRIU evaluation for the scoped Stage 15B participant."""
from __future__ import annotations

import json
import os
import shutil
import signal
import statistics
import sys
import tempfile
import time
from pathlib import Path

from .criu_participant import CRIUCheckpointParticipant
from .runtime import PolicyValidator, SessionManager, TransactionManager
from .stage15a import canonical_digest
from .stage15a3 import EligibilityStatus, ParticipantEligibility
from .stage15a_linux_runner import mutate, request, start, stop
from .stage15b import ExternalParticipantCoordinator, ExternalRollbackError


def eligible(participant_id: str) -> ParticipantEligibility:
    return ParticipantEligibility(
        participant_id, EligibilityStatus.ELIGIBLE_SINGLE_PROCESS, True, ()
    )


def runtime(accept: bool) -> tuple[SessionManager, TransactionManager, ExternalParticipantCoordinator]:
    sessions = SessionManager(); sessions.create_session("stage15b", user_id="research")
    manager = TransactionManager(sessions, validator=PolicyValidator(accept))
    return sessions, manager, ExternalParticipantCoordinator(manager)


def participant(kind: str, port: int, root: Path):
    process = start(kind, port)
    adapter = CRIUCheckpointParticipant(
        kind, process.pid, f"http://127.0.0.1:{port}", root, eligible(kind)
    )
    return process, adapter


def terminate(adapter: CRIUCheckpointParticipant) -> None:
    try: stop(adapter.pid)
    except Exception: pass


def rejected(kind: str, port: int, root: Path) -> dict[str, object]:
    sessions, manager, coordinator = runtime(False); process, adapter = participant(kind, port, root)
    initial = request(port); initial_digest = canonical_digest(initial)
    begin = time.perf_counter_ns(); tx = coordinator.begin("stage15b", adapter); begin_ns = time.perf_counter_ns() - begin
    mutate(kind, port); mutated = request(port)
    manager.write_private(tx, "stage15b", "session_memory", "contamination", "unsafe")
    manager.validate(tx); mark = time.perf_counter_ns(); coordinator.rollback(tx); rollback_ns = time.perf_counter_ns() - mark
    restored = request(port); result = {
        "kind": kind, "transaction_id": tx, "status": manager.status(tx).value,
        "local_restored": sessions.get_session("stage15b").session_memory == {},
        "external_restored": restored == initial,
        "initial": initial, "mutated": mutated, "restored": restored,
        "initial_digest": initial_digest, "restored_digest": canonical_digest(restored),
        "digest_match": initial_digest == canonical_digest(restored),
        "health_pass": adapter.health_check(), "fresh_reconnect": adapter.connected,
        "begin_ns": begin_ns, "rollback_ns": rollback_ns, **adapter.last_metrics,
        **(coordinator.enrollment(tx).metrics_ns or {}),
    }
    terminate(adapter); return result


def accepted(port: int, root: Path) -> dict[str, object]:
    sessions, manager, coordinator = runtime(True); _, adapter = participant("tool", port, root)
    tx = coordinator.begin("stage15b", adapter); handle = coordinator.enrollment(tx).handle
    mutate("tool", port); expected = request(port)
    manager.write_private(tx, "stage15b", "session_memory", "accepted", True); manager.validate(tx)
    mark = time.perf_counter_ns(); coordinator.commit(tx); commit_ns = time.perf_counter_ns() - mark
    result = {"status": manager.status(tx).value, "external_preserved": request(port) == expected,
              "local_committed": sessions.get_session("stage15b").session_memory == {"accepted": True},
              "checkpoint_released": not Path(handle.checkpoint_path).exists(), "commit_ns": commit_ns}
    terminate(adapter); return result


def restore_failure(port: int, root: Path) -> dict[str, object]:
    _, manager, coordinator = runtime(False); _, adapter = participant("tool", port, root)
    tx = coordinator.begin("stage15b", adapter); handle = coordinator.enrollment(tx).handle; mutate("tool", port)
    # Corrupt the real CRIU image set while retaining handle metadata as evidence.
    inventory = Path(handle.checkpoint_path) / "inventory.img"; inventory.rename(inventory.with_suffix(".injected-failure"))
    manager.validate(tx); error = None
    try: coordinator.rollback(tx)
    except ExternalRollbackError as exc: error = str(exc)
    result = {"status": manager.status(tx).value, "local_rollback": coordinator.enrollment(tx).local_rollback,
              "external_rollback": coordinator.enrollment(tx).external_rollback,
              "checkpoint_retained": Path(handle.checkpoint_path).exists(), "error": error}
    terminate(adapter); return result


def local_only(port: int) -> dict[str, object]:
    sessions, manager, coordinator = runtime(False); process = start("rag", port); initial = request(port)
    tx = coordinator.begin("stage15b"); mutate("rag", port); manager.write_private(tx, "stage15b", "session_memory", "poison", "unsafe")
    manager.validate(tx); mark = time.perf_counter_ns(); coordinator.rollback(tx); elapsed = time.perf_counter_ns() - mark
    result = {"local_restored": sessions.get_session("stage15b").session_memory == {},
              "external_contaminated": request(port) != initial, "rollback_ns": elapsed}
    stop(process.pid); return result


def local_performance(iterations: int = 30) -> dict[str, object]:
    begin, commit, rollback = [], [], []
    for index in range(iterations):
        sessions = SessionManager(); sessions.create_session(str(index)); manager = TransactionManager(sessions)
        mark = time.perf_counter_ns(); tx = manager.begin(str(index)); begin.append(time.perf_counter_ns() - mark)
        manager.validate(tx); mark = time.perf_counter_ns(); manager.commit(tx); commit.append(time.perf_counter_ns() - mark)
        tx = manager.begin(str(index)); manager.validate(tx); mark = time.perf_counter_ns(); manager.rollback(tx); rollback.append(time.perf_counter_ns() - mark)
    return {name: {"median_ns": statistics.median(values), "p95_ns": sorted(values)[int(.95 * len(values)) - 1]}
            for name, values in (("begin", begin), ("commit", commit), ("rollback", rollback))}


def main() -> None:
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "evaluation_results/stage15b/native_results.json")
    scratch = Path(tempfile.mkdtemp(prefix="stage15b-criu-"))
    try:
        tool = rejected("tool", 19510, scratch); rag = rejected("rag", 19511, scratch)
        result = {
            "environment": {"platform": sys.platform, "privileged_linuxkit": Path("/.dockerenv").exists()},
            "tool": tool, "rag": rag, "accepted_commit": accepted(19512, scratch),
            "restore_failure": restore_failure(19513, scratch),
            "comparison": {"application_only": local_only(19514), "expanded": rag},
            "realistic_agent": {"scenario": "Stage 13A-style malicious retrieval/cache persistence", **rag},
            "performance": {"local": local_performance(), "external_tool": {k: tool[k] for k in ("begin_ns", "rollback_ns", "checkpoint_ns", "restore_ns")}},
            "scope": "ELIGIBLE_SINGLE_PROCESS", "persistent_client_survival": False,
        }
        destination.parent.mkdir(parents=True, exist_ok=True); destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(result, indent=2, sort_keys=True))
    finally: shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__": main()
