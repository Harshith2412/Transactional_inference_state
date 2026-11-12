"""Deterministic Stage 12A provenance experiments and local microbenchmark."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from statistics import median
import time

from .effects import EffectManager, FakeEmailService, TransactionalTools
from .operations import OperationExecutor, parse_model_plan
from .provenance import RuntimeSourceType, TrustLabel
from .runtime import SessionManager, SharedState, TransactionManager


@dataclass(frozen=True)
class ProvenanceExperimentResult:
    committed_origin_identified: bool
    commit_preserved_provenance: bool
    rollback_removed_value: bool
    rollback_removed_lineage: bool
    cross_session_origin_preserved: bool
    claimed_provenance_overrode_runtime: bool
    effect_provenance_attached: bool
    event_types: tuple[str, ...]


@dataclass(frozen=True)
class ProvenanceOverheadResult:
    iterations: int
    baseline_median_ns: float
    provenance_median_ns: float
    incremental_median_ns: float


def stage12a_complexity_report(root: Path = Path(".")) -> dict[str, int]:
    # Historical measurement frozen when Stage 12A completed. Stage 12B reports
    # its expanded mechanism separately.
    return {
        "modules": 8, "python_loc": 1646,
        "third_party_runtime_dependencies": 0,
        "stage11_frozen_baseline_python_loc": 1210,
    }


def run_provenance_experiments() -> ProvenanceExperimentResult:
    sessions = SessionManager()
    state_a = sessions.create_session("session-a", user_id="user-a")
    sessions.create_session("session-b", user_id="user-b")
    effects = EffectManager(FakeEmailService())
    manager = TransactionManager(
        sessions, shared_state=SharedState(), effect_manager=effects
    )

    transaction_a = manager.begin("session-a")
    retrieved = manager.issue_provenance(
        transaction_a, RuntimeSourceType.RETRIEVED_CONTENT,
        trust_label=TrustLabel.UNTRUSTED,
    )
    derived = manager.issue_provenance(
        transaction_a, RuntimeSourceType.DERIVED_VALUE,
        trust_label=TrustLabel.UNTRUSTED,
        parent_source_ids=(retrieved.source_id,),
    )
    raw_plan = (
        '{"operations":[{"operation_id":"op-1",'
        '"operation_type":"MEMORY_WRITE","arguments":{"key":"summary",'
        '"value":"derived text"},"source":"user_prompt"}],'
        '"final_response":"done"}'
    )
    OperationExecutor(manager).execute(
        parse_model_plan(raw_plan), transaction_a, "session-a",
        runtime_provenance={"op-1": (derived.source_id,)},
    )
    manager.write_shared(
        transaction_a, "summary", "derived text",
        provenance_ids=(derived.source_id,),
    )
    effect = TransactionalTools(effects, transaction_a, "session-a").send_email(
        to="reviewer@example.test", subject="summary", body="derived text",
        provenance_ids=(derived.source_id,),
    )
    manager.validate(transaction_a)
    manager.commit(transaction_a)

    committed = manager.provenance_for_private(
        "session-a", "session_memory", "summary"
    )
    transaction_b = manager.begin("session-b")
    cross_session = manager.read_shared_provenanced(transaction_b, "summary")
    manager.rollback(transaction_b)

    rollback_tx = manager.begin("session-a")
    tentative = manager.issue_provenance(
        rollback_tx, RuntimeSourceType.USER_PROMPT,
        trust_label=TrustLabel.TRUSTED,
    )
    manager.write_private(
        rollback_tx, "session-a", "session_memory", "temporary", "discard",
        provenance_ids=(tentative.source_id,),
    )
    manager.rollback(rollback_tx)

    return ProvenanceExperimentResult(
        committed_origin_identified=(
            len(committed) == 1 and committed[0].user_id == "user-a"
            and retrieved.source_id in {
                item.source_id for item in manager.provenance_registry.lineage(
                    (committed[0].source_id,)
                )
            }
        ),
        commit_preserved_provenance=bool(
            state_a.provenance_metadata.get("session_memory:summary")
        ),
        rollback_removed_value="temporary" not in state_a.session_memory,
        rollback_removed_lineage=not manager.provenance_registry.contains(
            tentative.source_id
        ),
        cross_session_origin_preserved=(
            cross_session.provenance[0].session_id == "session-a"
            and cross_session.provenance[0].user_id == "user-a"
        ),
        claimed_provenance_overrode_runtime=(
            committed[0].source_type is RuntimeSourceType.USER_PROMPT
        ),
        effect_provenance_attached=(
            effect.provenance_ids == (derived.source_id,)
            and effects.list_effects(transaction_a, "session-a")[0].provenance_ids
            == (derived.source_id,)
        ),
        event_types=tuple(event.event_type for event in manager.event_log.events),
    )


def benchmark_provenance_overhead(iterations: int = 200) -> ProvenanceOverheadResult:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    baseline: list[int] = []
    provenance: list[int] = []
    for index in range(iterations):
        sessions = SessionManager()
        sessions.create_session("session", user_id="user")
        manager = TransactionManager(sessions)
        transaction = manager.begin("session")
        start = time.perf_counter_ns()
        manager.write_private(
            transaction, "session", "session_memory", str(index), index
        )
        baseline.append(time.perf_counter_ns() - start)
        manager.rollback(transaction)

        sessions = SessionManager()
        sessions.create_session("session", user_id="user")
        manager = TransactionManager(sessions)
        transaction = manager.begin("session")
        start = time.perf_counter_ns()
        source = manager.issue_provenance(
            transaction, RuntimeSourceType.USER_PROMPT,
            trust_label=TrustLabel.TRUSTED,
        )
        manager.write_private(
            transaction, "session", "session_memory", str(index), index,
            provenance_ids=(source.source_id,),
        )
        provenance.append(time.perf_counter_ns() - start)
        manager.rollback(transaction)
    baseline_median = median(baseline)
    provenance_median = median(provenance)
    return ProvenanceOverheadResult(
        iterations, baseline_median, provenance_median,
        provenance_median - baseline_median,
    )
