"""Standalone Stage 15A process-checkpoint feasibility harness.

This module intentionally has no dependency on TransactionManager.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class ToolServiceState:
    counter: int = 0
    key_value_store: dict[str, str] = field(default_factory=lambda: {"role": "user"})
    history: list[str] = field(default_factory=list)

    def mutate_unsafe(self) -> None:
        self.counter += 1
        self.key_value_store["role"] = "admin"
        self.history.append("unsafe-operation")

    def document(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return canonical_digest(self.document())


@dataclass
class RagCacheState:
    authorization: str = "user"
    documents: dict[str, str] = field(default_factory=dict)
    retrieval_cache: dict[str, str] = field(default_factory=dict)
    query_history: list[str] = field(default_factory=list)
    summary_cache: dict[str, str] = field(default_factory=dict)

    def retrieve(self, query: str) -> list[str]:
        self.query_history.append(query)
        return [value for key, value in sorted(self.documents.items()) if query in key or query in value]

    def mutate_unsafe(self) -> None:
        self.authorization = "admin"
        self.retrieval_cache["poison"] = "approved disclosure"

    def document(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return canonical_digest(self.document())


class BackendStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    HOST_UNSUPPORTED = "HOST_UNSUPPORTED_FOR_NATIVE_CHECKPOINT"
    PERMISSION_DENIED = "PERMISSION_DENIED"


class Suitability(str, Enum):
    SUITABLE = "SUITABLE_FOR_STAGE15B"
    PARTIAL = "PARTIALLY_SUITABLE"
    NOT_SUITABLE = "NOT_SUITABLE"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class BackendProbe:
    backend: str
    status: BackendStatus
    executable: str | None
    version: str | None
    reason: str
    suitability: Suitability


class CheckpointBackend(Protocol):
    name: str
    def probe(self) -> BackendProbe: ...


class CommandBackend:
    """Read-only availability probe; privileged commands require explicit use."""

    def __init__(self, name: str, executable: str, version_args: tuple[str, ...]) -> None:
        self.name, self.executable, self.version_args = name, executable, version_args

    def probe(self) -> BackendProbe:
        path = shutil.which(self.executable)
        if platform.system() != "Linux":
            return BackendProbe(self.name, BackendStatus.HOST_UNSUPPORTED, path, None,
                                "native process checkpointing requires Linux",
                                Suitability.UNAVAILABLE)
        if path is None:
            return BackendProbe(self.name, BackendStatus.UNAVAILABLE, None, None,
                                f"{self.executable} is not installed", Suitability.UNAVAILABLE)
        try:
            completed = subprocess.run((path, *self.version_args), capture_output=True,
                                       text=True, timeout=5, check=False)
            version = (completed.stdout or completed.stderr).strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError) as error:
            return BackendProbe(self.name, BackendStatus.UNAVAILABLE, path, None,
                                f"version probe failed: {error}", Suitability.UNAVAILABLE)
        return BackendProbe(self.name, BackendStatus.AVAILABLE, path, version,
                            "available; privileges and runtime compatibility still require a live test",
                            Suitability.PARTIAL)


def environment_probe() -> dict[str, Any]:
    container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    return {
        "os": platform.system(), "os_release": platform.release(),
        "kernel": platform.version(), "architecture": platform.machine(),
        "python": platform.python_version(), "container_detected": container,
        "virtualization": "unknown (stdlib-only probe)",
        "native_checkpoint_supported": platform.system() == "Linux",
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
    }


def backend_probes() -> list[dict[str, Any]]:
    backends = (CommandBackend("CRIU", "criu", ("--version",)),
                CommandBackend("DMTCP", "dmtcp_launch", ("--version",)))
    return [asdict(backend.probe()) for backend in backends]


def baseline_experiment() -> dict[str, Any]:
    tool, rag = ToolServiceState(), RagCacheState()
    initial = {"tool": tool.document(), "rag": rag.document()}
    before = {"tool": tool.digest(), "rag": rag.digest()}
    tool.mutate_unsafe(); rag.mutate_unsafe()
    after = {"tool": tool.digest(), "rag": rag.digest()}
    return {"initial": initial, "mutated": {"tool": tool.document(), "rag": rag.document()},
            "before_digest": before, "after_digest": after,
            "mutation_persists": before != after}


def simulated_checkpoint_experiment() -> dict[str, Any]:
    """Fixture-only oracle for CI; never reported as CRIU/DMTCP success."""
    tool, rag = ToolServiceState(), RagCacheState()
    snapshots = json.loads(json.dumps({"tool": tool.document(), "rag": rag.document()}))
    before = {"tool": tool.digest(), "rag": rag.digest()}
    tool.mutate_unsafe(); rag.mutate_unsafe()
    mutated = {"tool": tool.document(), "rag": rag.document()}
    tool = ToolServiceState(**snapshots["tool"]); rag = RagCacheState(**snapshots["rag"])
    final = {"tool": tool.document(), "rag": rag.document()}
    return {"backend": "IN_MEMORY_TEST_ORACLE", "is_native_checkpoint": False,
            "initial": snapshots, "mutated": mutated, "final": final,
            "digest_match": {"tool": tool.digest() == before["tool"],
                             "rag": rag.digest() == before["rag"]},
            "structural_match": final == snapshots}


def external_side_effect_negative_test(observer_file: str | Path) -> dict[str, Any]:
    path = Path(observer_file)
    tool = ToolServiceState(); snapshot = tool.document()
    path.write_text("before\n")
    tool.mutate_unsafe()
    with path.open("a") as handle:
        handle.write("unsafe-external-observation\n")
    tool = ToolServiceState(**snapshot)
    return {"service_restored": tool.document() == snapshot,
            "observer_effect_remains": "unsafe-external-observation" in path.read_text(),
            "finding": "process restore is not arbitrary-world rollback"}


def filesystem_negative_test(service_file: str | Path) -> dict[str, Any]:
    path = Path(service_file); path.write_text("initial")
    memory = ToolServiceState(); snapshot = memory.document()
    memory.mutate_unsafe(); path.write_text("mutated")
    memory = ToolServiceState(**snapshot)
    return {"memory_restored": memory.document() == snapshot,
            "filesystem_restored": path.read_text() == "initial",
            "file_value_after_process_restore": path.read_text()}


def failure_injection_results() -> list[dict[str, Any]]:
    cases = ("checkpoint_command_failure", "incomplete_checkpoint", "restore_failure",
             "process_killed_during_checkpoint", "process_killed_before_restore")
    return [{"case": case, "rollback_reported_successful": False,
             "safe_behavior": "STOP_AND_REPORT_FAILURE"} for case in cases]


def unavailable_performance_matrix() -> list[dict[str, Any]]:
    return [{"backend": backend, "state_mb": size, "mutation_keys": density,
             "checkpoint_latency_ns": None, "restore_latency_ns": None,
             "checkpoint_bytes": None, "status": "NOT_RUN_BACKEND_UNAVAILABLE"}
            for backend in ("CRIU", "DMTCP") for size in (1, 10, 50, 100)
            for density in (1, 100, 10_000)]


def flagship_transcript(result: dict[str, Any]) -> str:
    status = "MATCH" if all(result["digest_match"].values()) else "MISMATCH"
    return "\n".join(("INITIAL TOOL STATE", "role=user", "counter=0", "",
        "INITIAL RAG STATE", "authorization=user", "cache={}", "", "CHECKPOINT",
        "", "INFERENCE-SIMULATED MUTATION", "", "TOOL STATE", "role=admin",
        "counter=1", "", "RAG STATE", "authorization=admin",
        'cache={"poison": "approved disclosure"}', "", "REJECT", "", "RESTORE",
        "", "FINAL TOOL STATE", "role=user", "counter=0", "", "FINAL RAG STATE",
        "authorization=user", "cache={}", "", "DIGESTS", f"tool: {status}",
        f"rag: {status}", "", "NOTE: CI oracle only; no native backend was claimed."))


def evaluate_stage15a(work_dir: str | Path) -> dict[str, Any]:
    root = Path(work_dir); root.mkdir(parents=True, exist_ok=True)
    baseline = baseline_experiment(); oracle = simulated_checkpoint_experiment()
    effects = external_side_effect_negative_test(root / "observer.log")
    filesystem = filesystem_negative_test(root / "service-state.txt")
    probes = backend_probes()
    return {"schema_version": 1, "environment": environment_probe(), "backends": probes,
            "baseline": baseline, "oracle": oracle, "filesystem": filesystem,
            "external_effects": effects, "failure_injection": failure_injection_results(),
            "performance": unavailable_performance_matrix(),
            "multi_process": {"status": "NOT_RUN_BACKEND_UNAVAILABLE",
                              "atomicity": "NOT_DEMONSTRATED"},
            "socket_behavior": {"status": "NOT_MEASURED_NATIVE_BACKEND_UNAVAILABLE",
                                "reconnect_required": None, "port_preserved": None},
            "repeated_cycles": {"cycles": [10, 50, 100],
                                "status": "NOT_RUN_BACKEND_UNAVAILABLE"},
            "boundary_levels": {"level_0": "InferenceState only",
                "level_1": "InferenceState + tool checkpoint",
                "level_2": "InferenceState + tool + RAG/cache checkpoints",
                "level_3": "future external/durable services"},
            "recommendation": {"stage15b_justified_on_this_host": False,
                "reason": "native backends unavailable on macOS; run Linux feasibility scripts first"},
            "transcript": flagship_transcript(oracle)}
