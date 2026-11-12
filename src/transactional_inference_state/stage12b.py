"""Stage 12B correctness experiments and synthetic three-strategy benchmark."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, fields, is_dataclass
import json
from pathlib import Path
from statistics import median
import time
import tracemalloc
from typing import Any, Iterable

from .cow import FieldPath, FineGrainedCOWStrategy
from .integrity import state_digest
from .provenance import RuntimeSourceType, TrustLabel
from .runtime import (
    DeltaStrategy, FullCopyStrategy, InferenceState, SessionManager,
    TransactionManager,
)


@dataclass(frozen=True)
class COWCorrectnessResult:
    outcome: str
    committed_before: bool
    tentative_value: bool
    committed_after: bool
    structural_integrity: bool
    tentative_provenance_disappeared: bool
    modified_field_new_provenance: bool
    name_provenance_unchanged: bool
    editor_provenance_unchanged: bool
    copied_nodes: int
    modified_paths: int
    copy_amplification: float
    full_materialization_occurred: bool


@dataclass(frozen=True)
class COWBenchmarkRecord:
    strategy: str
    state_size: str
    target_bytes: int
    mutation_ratio: float
    mutation_depth: int
    outcome: str
    begin_ns: int
    read_ns: int
    mutation_ns: int
    validation_ns: int
    closure_ns: int
    total_ns: int
    peak_traced_bytes: int
    changed_field_count: int
    copied_node_count: int
    logically_modified_nodes: int
    copy_amplification: float
    full_materialization_occurred: bool
    rollback_integrity: bool
    provenance_integrity: bool


@dataclass(frozen=True)
class COWProvenanceOverhead:
    iterations: int
    mutation_without_provenance_median_ns: float
    mutation_with_provenance_median_ns: float
    incremental_provenance_ns: float


SIZE_BYTES = {
    "10KB": 10 * 1024,
    "100KB": 100 * 1024,
    "1MB": 1024 * 1024,
    "10MB": 10 * 1024 * 1024,
    "50MB": 50 * 1024 * 1024,
}


def stage12b_complexity_report(root: Path = Path(".")) -> dict[str, int]:
    source = root / "src" / "transactional_inference_state"
    names = (
        "runtime.py", "policy.py", "provenance.py", "budgets.py", "effects.py",
        "operations.py", "integrity.py", "stage12a.py", "cow.py",
    )
    paths = [source / name for name in names]
    loc = sum(
        1 for path in paths for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    return {
        "modules": len(paths), "python_loc": loc,
        "third_party_runtime_dependencies": 0,
        "stage12a_frozen_modules": 8,
        "stage12a_frozen_python_loc": 1646,
    }


def run_flagship_cow_experiment(outcome: str) -> COWCorrectnessResult:
    if outcome not in {"commit", "rollback"}:
        raise ValueError("outcome must be commit or rollback")
    sessions, manager = _flagship_runtime()
    state = sessions.get_session("S1")
    target = FieldPath.keys(
        "session_memory", "profile", "authorization", "external_sharing"
    )
    name = FieldPath.keys("session_memory", "profile", "name")
    editor = FieldPath.keys(
        "session_memory", "profile", "preferences", "editor"
    )
    name_sources = tuple(x.source_id for x in manager.provenance_for_path("S1", name))
    editor_sources = tuple(x.source_id for x in manager.provenance_for_path("S1", editor))
    original_target = tuple(
        x.source_id for x in manager.provenance_for_path("S1", target)
    )
    before_digest = state_digest(state)
    transaction = manager.begin("S1")
    retrieval = manager.issue_provenance(
        transaction, RuntimeSourceType.RETRIEVED_CONTENT,
        trust_label=TrustLabel.UNTRUSTED,
    )
    committed_before = state.session_memory["profile"]["authorization"]["external_sharing"]
    manager.write_path(
        transaction, "S1", target, True,
        provenance_ids=(retrieval.source_id,),
    )
    tentative = manager.read_path(transaction, "S1", target)
    accounting = manager.cow_accounting(transaction)
    manager.validate(transaction)
    if outcome == "commit":
        manager.commit(transaction)
    else:
        manager.rollback(transaction)
    committed_after = state.session_memory["profile"]["authorization"]["external_sharing"]
    target_sources = tuple(
        x.source_id for x in manager.provenance_for_path("S1", target)
    )
    return COWCorrectnessResult(
        outcome=outcome,
        committed_before=committed_before,
        tentative_value=tentative,
        committed_after=committed_after,
        structural_integrity=(
            state_digest(state) == before_digest if outcome == "rollback"
            else state.session_memory["profile"]["name"] == "Alice"
            and state.session_memory["profile"]["preferences"]["editor"] == "VS Code"
        ),
        tentative_provenance_disappeared=(
            not manager.provenance_registry.contains(retrieval.source_id)
            if outcome == "rollback" else False
        ),
        modified_field_new_provenance=(
            target_sources == ((retrieval.source_id,) if outcome == "commit"
                               else original_target)
        ),
        name_provenance_unchanged=tuple(
            x.source_id for x in manager.provenance_for_path("S1", name)
        ) == name_sources,
        editor_provenance_unchanged=tuple(
            x.source_id for x in manager.provenance_for_path("S1", editor)
        ) == editor_sources,
        copied_nodes=accounting.cow_nodes_copied,
        modified_paths=accounting.cow_paths_modified,
        copy_amplification=accounting.copy_amplification,
        full_materialization_occurred=accounting.full_materialization_occurred,
    )


def _flagship_runtime() -> tuple[SessionManager, TransactionManager]:
    sessions = SessionManager()
    state = sessions.create_session("S1", user_id="A")
    state.session_memory["profile"] = {
        "name": "Alice",
        "preferences": {"editor": "VS Code"},
        "authorization": {"external_sharing": False},
    }
    manager = TransactionManager(
        sessions, snapshot_strategy=FineGrainedCOWStrategy()
    )
    transaction = manager.begin("S1")
    name_source = manager.issue_provenance(
        transaction, RuntimeSourceType.USER_INPUT,
        trust_label=TrustLabel.TRUSTED,
    )
    editor_source = manager.issue_provenance(
        transaction, RuntimeSourceType.USER_INPUT,
        trust_label=TrustLabel.TRUSTED,
    )
    authorization_source = manager.issue_provenance(
        transaction, RuntimeSourceType.SYSTEM_CONTEXT,
        trust_label=TrustLabel.TRUSTED,
    )
    manager.write_path(
        transaction, "S1", FieldPath.keys("session_memory", "profile", "name"),
        "Alice", provenance_ids=(name_source.source_id,),
    )
    manager.write_path(
        transaction, "S1",
        FieldPath.keys("session_memory", "profile", "preferences", "editor"),
        "VS Code", provenance_ids=(editor_source.source_id,),
    )
    manager.write_path(
        transaction, "S1", FieldPath.keys(
            "session_memory", "profile", "authorization", "external_sharing"
        ), False, provenance_ids=(authorization_source.source_id,),
    )
    manager.validate(transaction)
    manager.commit(transaction)
    return sessions, manager


def run_cow_benchmark(
    *, sizes: tuple[str, ...] = ("10KB", "100KB", "1MB"),
    mutation_ratios: tuple[float, ...] = (0.01, 0.10, 1.0),
    depths: tuple[int, ...] = (3,), iterations: int = 1,
) -> list[COWBenchmarkRecord]:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    records: list[COWBenchmarkRecord] = []
    for size in sizes:
        if size not in SIZE_BYTES:
            raise ValueError(f"unknown size: {size}")
        for ratio in mutation_ratios:
            if not 0 < ratio <= 1:
                raise ValueError("mutation ratios must be in (0, 1]")
            for depth in depths:
                if depth < 1:
                    raise ValueError("depth must be positive")
                for strategy in (
                    FullCopyStrategy(), DeltaStrategy(), FineGrainedCOWStrategy()
                ):
                    for outcome in ("commit", "rollback"):
                        candidates = [_benchmark_one(
                            strategy, size, ratio, depth, outcome
                        ) for _ in range(iterations)]
                        records.append(min(candidates, key=lambda row: row.total_ns)
                                       if iterations == 1 else _median_record(candidates))
    return records


def _benchmark_one(strategy: Any, size: str, ratio: float, depth: int,
                   outcome: str) -> COWBenchmarkRecord:
    state, paths = _benchmark_state(SIZE_BYTES[size], depth)
    sessions = SessionManager()
    committed = sessions.create_session("benchmark", user_id="benchmark-user")
    committed.session_memory = state.session_memory
    before = state_digest(committed)
    changed = max(1, round(len(paths) * ratio))
    selected = paths[:changed]
    tracemalloc.start()
    total_start = time.perf_counter_ns()
    start = time.perf_counter_ns()
    manager = TransactionManager(sessions, snapshot_strategy=strategy)
    transaction = manager.begin("benchmark")
    begin_ns = time.perf_counter_ns() - start
    start = time.perf_counter_ns()
    if isinstance(strategy, FineGrainedCOWStrategy):
        for path in selected:
            manager.read_path(transaction, "benchmark", path)
    else:
        top_keys = tuple(dict.fromkeys(path.components[0].value for path in selected))
        for key in top_keys:
            manager.read_private(transaction, "benchmark", "session_memory", key)
    read_ns = time.perf_counter_ns() - start
    start = time.perf_counter_ns()
    if isinstance(strategy, FineGrainedCOWStrategy):
        for index, path in enumerate(selected):
            manager.write_path(transaction, "benchmark", path, f"changed-{index}")
    else:
        grouped: dict[str, list[tuple[FieldPath, int]]] = {}
        for index, path in enumerate(selected):
            grouped.setdefault(path.components[0].value, []).append((path, index))
        for key, changes in grouped.items():
            branch = manager.read_private(
                transaction, "benchmark", "session_memory", key
            )
            for path, index in changes:
                if len(path.components) == 1:
                    branch = f"changed-{index}"
                else:
                    _plain_set(branch, path.components[1:], f"changed-{index}")
            manager.write_private(
                transaction, "benchmark", "session_memory", key, branch
            )
    mutation_ns = time.perf_counter_ns() - start
    start = time.perf_counter_ns()
    manager.validate(transaction)
    validation_ns = time.perf_counter_ns() - start
    start = time.perf_counter_ns()
    if outcome == "commit":
        manager.commit(transaction)
    else:
        manager.rollback(transaction)
    closure_ns = time.perf_counter_ns() - start
    total_ns = time.perf_counter_ns() - total_start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    copied, amplification, materialized = _copy_accounting(
        strategy, manager, transaction, committed, selected, outcome
    )
    return COWBenchmarkRecord(
        strategy.name, size, SIZE_BYTES[size], ratio, depth, outcome,
        begin_ns, read_ns, mutation_ns, validation_ns, closure_ns, total_ns,
        peak, changed, copied, changed, amplification, materialized,
        state_digest(committed) == before if outcome == "rollback" else True,
        committed.provenance_metadata == {},
    )


def _benchmark_state(target_bytes: int, depth: int,
                     fields: int = 100) -> tuple[InferenceState, list[FieldPath]]:
    payload_size = max(1, target_bytes // fields - 80)
    memory: dict[str, Any] = {}
    paths: list[FieldPath] = []
    for index in range(fields):
        key = f"item-{index:03d}"
        value: Any = "x" * payload_size
        nested_keys = [f"level-{level}" for level in range(1, depth)]
        for nested_key in reversed(nested_keys):
            value = {nested_key: value}
        memory[key] = value
        paths.append(FieldPath.keys("session_memory", key, *nested_keys))
    return InferenceState(session_memory=memory), paths


def _plain_set(container: Any, components: tuple[Any, ...], value: Any) -> None:
    current = container
    for component in components[:-1]:
        current = current[component.value]
    current[components[-1].value] = value


def _node_count(value: Any) -> int:
    if is_dataclass(value):
        return 1 + sum(_node_count(getattr(value, item.name))
                       for item in fields(value))
    if isinstance(value, dict):
        return 1 + sum(_node_count(item) for item in value.values())
    if isinstance(value, list):
        return 1 + sum(_node_count(item) for item in value)
    return 1


def _copy_accounting(strategy: Any, manager: TransactionManager,
                     transaction: str, committed: InferenceState,
                     selected: list[FieldPath], outcome: str) -> tuple[int, float, bool]:
    logical = max(1, len(selected))
    if isinstance(strategy, FineGrainedCOWStrategy):
        accounting = manager.cow_accounting(transaction)
        return (accounting.cow_nodes_copied, accounting.copy_amplification,
                accounting.full_materialization_occurred)
    if isinstance(strategy, FullCopyStrategy):
        nodes = _node_count(committed) * (2 if outcome == "commit" else 1)
        return nodes, nodes / logical, False
    top_keys = set(path.components[0].value for path in selected)
    branch_nodes = sum(_node_count(committed.session_memory[key])
                       for key in top_keys)
    nodes = branch_nodes * (3 if outcome == "commit" else 2)
    return nodes, nodes / logical, False


def benchmark_cow_provenance_overhead(iterations: int = 500) -> COWProvenanceOverhead:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    plain: list[int] = []
    labelled: list[int] = []
    path = FieldPath.keys("session_memory", "profile", "value")
    for index in range(iterations):
        for with_provenance, samples in ((False, plain), (True, labelled)):
            sessions = SessionManager()
            state = sessions.create_session("S", user_id="U")
            state.session_memory["profile"] = {"value": 0, "sibling": "same"}
            manager = TransactionManager(
                sessions, snapshot_strategy=FineGrainedCOWStrategy()
            )
            transaction = manager.begin("S")
            start = time.perf_counter_ns()
            source_ids: tuple[str, ...] = ()
            if with_provenance:
                source = manager.issue_provenance(
                    transaction, RuntimeSourceType.USER_INPUT,
                    trust_label=TrustLabel.TRUSTED,
                )
                source_ids = (source.source_id,)
            manager.write_path(
                transaction, "S", path, index,
                provenance_ids=source_ids,
            )
            samples.append(time.perf_counter_ns() - start)
            manager.rollback(transaction)
    plain_median, labelled_median = median(plain), median(labelled)
    return COWProvenanceOverhead(
        iterations, plain_median, labelled_median,
        labelled_median - plain_median,
    )


def _median_record(records: list[COWBenchmarkRecord]) -> COWBenchmarkRecord:
    values = asdict(records[0])
    numeric = (
        "begin_ns", "read_ns", "mutation_ns", "validation_ns", "closure_ns",
        "total_ns", "peak_traced_bytes", "copied_node_count",
        "copy_amplification",
    )
    for name in numeric:
        values[name] = median(getattr(record, name) for record in records)
    values["rollback_integrity"] = all(x.rollback_integrity for x in records)
    values["provenance_integrity"] = all(x.provenance_integrity for x in records)
    values["full_materialization_occurred"] = any(
        x.full_materialization_occurred for x in records
    )
    return COWBenchmarkRecord(**values)


def export_stage12b(records: Iterable[COWBenchmarkRecord], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    rows = [asdict(record) for record in records]
    (output / "raw_results.json").write_text(json.dumps(rows, indent=2))
