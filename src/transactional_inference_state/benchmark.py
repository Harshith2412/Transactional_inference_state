"""Deterministic workloads and local snapshot-strategy benchmarks."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import statistics
import time
import tracemalloc
from typing import Any

from .integrity import canonical_state_bytes, state_digest
from .runtime import (
    DeltaStrategy,
    FullCopyStrategy,
    InferenceState,
    PolicyValidator,
    SessionManager,
    SnapshotStrategy,
    TransactionManager,
)


SIZE_PRESETS = {
    "10KB": 10 * 1024,
    "100KB": 100 * 1024,
    "1MB": 1024 * 1024,
    "10MB": 10 * 1024 * 1024,
    "50MB": 50 * 1024 * 1024,
}


def generate_benchmark_state(target_bytes: int) -> InferenceState:
    """Generate deterministic JSON-compatible state near the requested size."""
    if target_bytes < 512:
        raise ValueError("target_bytes must be at least 512")
    state = InferenceState(user_session_metadata={"generator": "stage-3"})
    base_size = len(canonical_state_bytes(state))
    chunk_size = min(16 * 1024, max(256, target_bytes - base_size - 48))
    estimated_entry_size = chunk_size + 48
    entry_count = max(1, (target_bytes - base_size) // estimated_entry_size)
    for index in range(entry_count):
        key = f"item-{index:08d}"
        state.session_memory[key] = (f"payload-{index:08d}-" + "x" * chunk_size)
    current_size = len(canonical_state_bytes(state))
    if current_size > target_bytes:
        last_key = f"item-{entry_count - 1:08d}"
        value = state.session_memory[last_key]
        excess = current_size - target_bytes
        state.session_memory[last_key] = value[:max(1, len(value) - excess)]
        current_size = len(canonical_state_bytes(state))
    if current_size < target_bytes:
        index = entry_count
        key = f"item-{index:08d}"
        prefix = f"payload-{index:08d}-"
        # ASCII payload bytes map one-to-one to canonical JSON bytes.
        state.session_memory[key] = prefix
        short_size = len(canonical_state_bytes(state))
        state.session_memory[key] += "x" * max(0, target_bytes - short_size)
    return state


@dataclass(frozen=True)
class MetricSummary:
    """Descriptive nanosecond statistics for one measured transaction phase."""
    mean_ns: float
    median_ns: float
    min_ns: int
    max_ns: int
    stdev_ns: float


@dataclass(frozen=True)
class BenchmarkResult:
    """Structured repeated-workload result; allocation is tracemalloc, not RSS."""
    strategy: str
    state_size_bytes: int
    mutation_ratio: float
    operation_type: str
    iterations: int
    phase_metrics: dict[str, MetricSummary]
    mean_latency_ns: float
    median_latency_ns: float
    min_latency_ns: int
    max_latency_ns: int
    stdev_latency_ns: float
    mean_memory_overhead_bytes: float
    rollback_integrity: bool
    mutated_keys: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _summary(values: list[int]) -> MetricSummary:
    return MetricSummary(
        mean_ns=statistics.mean(values),
        median_ns=statistics.median(values),
        min_ns=min(values),
        max_ns=max(values),
        stdev_ns=statistics.pstdev(values),
    )


def run_benchmark(
    strategy: SnapshotStrategy,
    *,
    target_bytes: int = SIZE_PRESETS["10KB"],
    mutation_ratio: float = 0.01,
    operation_type: str = "rollback",
    iterations: int = 3,
) -> BenchmarkResult:
    if not 0 < mutation_ratio <= 1:
        raise ValueError("mutation_ratio must be in (0, 1]")
    if operation_type not in {"commit", "rollback"}:
        raise ValueError("operation_type must be commit or rollback")
    if iterations < 1:
        raise ValueError("iterations must be positive")
    template = generate_benchmark_state(target_bytes)
    actual_size = len(canonical_state_bytes(template))
    phases = {name: [] for name in
              ("begin", "mutation", "validation", operation_type, "total")}
    memory_samples: list[int] = []
    integrity_samples: list[bool] = []

    for iteration in range(iterations):
        sessions = SessionManager()
        committed = sessions.create_session("benchmark")
        for name, value in vars(deepcopy(template)).items():
            setattr(committed, name, value)
        before = deepcopy(committed)
        before_digest = state_digest(committed)
        accepted = operation_type == "commit"
        manager = TransactionManager(
            sessions, snapshot_strategy=strategy,
            validator=PolicyValidator(accepted),
        )
        keys = sorted(committed.session_memory)
        mutation_count = max(1, round(len(keys) * mutation_ratio))
        selected = keys[:mutation_count]

        tracemalloc.start()
        total_start = time.perf_counter_ns()
        start = time.perf_counter_ns()
        transaction_id = manager.begin("benchmark")
        phases["begin"].append(time.perf_counter_ns() - start)

        start = time.perf_counter_ns()
        for key in selected:
            manager.write_private(
                transaction_id, "benchmark", "session_memory", key,
                f"mutated-{iteration}-{key}",
            )
        phases["mutation"].append(time.perf_counter_ns() - start)

        start = time.perf_counter_ns()
        manager.validate(transaction_id)
        phases["validation"].append(time.perf_counter_ns() - start)

        start = time.perf_counter_ns()
        if accepted:
            manager.commit(transaction_id)
        else:
            manager.rollback(transaction_id)
        phases[operation_type].append(time.perf_counter_ns() - start)
        phases["total"].append(time.perf_counter_ns() - total_start)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        memory_samples.append(peak)
        if accepted:
            integrity_samples.append(all(
                committed.session_memory[key] == f"mutated-{iteration}-{key}"
                for key in selected
            ))
        else:
            integrity_samples.append(
                committed == before and state_digest(committed) == before_digest
            )

    totals = _summary(phases["total"])
    return BenchmarkResult(
        strategy=strategy.name,
        state_size_bytes=actual_size,
        mutation_ratio=mutation_ratio,
        operation_type=operation_type,
        iterations=iterations,
        phase_metrics={name: _summary(values) for name, values in phases.items()},
        mean_latency_ns=totals.mean_ns,
        median_latency_ns=totals.median_ns,
        min_latency_ns=totals.min_ns,
        max_latency_ns=totals.max_ns,
        stdev_latency_ns=totals.stdev_ns,
        mean_memory_overhead_bytes=statistics.mean(memory_samples),
        rollback_integrity=all(integrity_samples),
        mutated_keys=mutation_count,
    )


def small_strategy_comparison(iterations: int = 3) -> list[BenchmarkResult]:
    results = []
    for strategy in (FullCopyStrategy(), DeltaStrategy()):
        for operation in ("commit", "rollback"):
            results.append(run_benchmark(
                strategy, target_bytes=SIZE_PRESETS["10KB"],
                mutation_ratio=0.05, operation_type=operation,
                iterations=iterations,
            ))
    return results
