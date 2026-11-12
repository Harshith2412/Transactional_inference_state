"""Stage 12C deterministic flow attacks, flagships, concurrency, and overhead."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import median
import threading
import time
from typing import Any

from .flow import (
    DeclassificationRegistry, FilteredFlowResult, FlowDecision, FlowOutcome,
    FlowPolicy, SecurityPrincipal,
)
from .provenance import RuntimeSourceType, TrustLabel
from .cow import FineGrainedCOWStrategy
from .runtime import SessionManager, SharedState, TransactionManager, WriteConflictError


@dataclass(frozen=True)
class FlowTrial:
    scenario_id: str
    attack_family: str
    field: str
    expected_authorized: bool
    policy_allowed: bool
    outcome: str
    leaked: bool
    false_block: bool


@dataclass(frozen=True)
class MixedFieldExperiment:
    before_value: dict[str, Any]
    before_outcomes: dict[str, str]
    after_value: dict[str, Any]
    after_outcomes: dict[str, str]
    provenance_unchanged: bool
    restricted_fields_leaked: int


@dataclass(frozen=True)
class LabelStrippingExperiment:
    raw_value_stored: bool
    outcome: str
    allowed: bool
    leaked: bool


@dataclass(frozen=True)
class LaunderingExperiment:
    chain_source_ids: tuple[str, ...]
    root_users: tuple[str, ...]
    root_sessions: tuple[str, ...]
    root_transactions: tuple[str, ...]
    outcome: str
    allowed: bool
    leaked: bool


@dataclass(frozen=True)
class ConcurrencyResult:
    sessions: int
    total_transactions: int
    completed_transactions: int
    flow_decisions: int
    blocked_flows: int
    allowed_declassified_flows: int
    public_flows_allowed: int
    unauthorized_flows_allowed: int
    valid_flows_false_blocked: int
    conflict_aborts: int
    rollback_integrity: bool
    throughput_transactions_per_second: float
    median_latency_ns: float
    p95_latency_ns: float


@dataclass(frozen=True)
class FlowOverheadResult:
    iterations: int
    baseline_field_read_median_ns: float
    provenance_field_read_median_ns: float
    same_session_check_median_ns: float
    cross_session_denied_median_ns: float
    cross_session_declassified_median_ns: float


@dataclass
class _Fixture:
    sessions: SessionManager
    manager: TransactionManager
    declassifications: DeclassificationRegistry
    policy: FlowPolicy
    principal_a: SecurityPrincipal
    principal_b: SecurityPrincipal
    source_ids: dict[str, str]


def flagship_flow_experiment() -> MixedFieldExperiment:
    fixture = _base_fixture()
    before_sources = {
        field: tuple(source.source_id for source in fixture.manager.provenance_registry.lineage((source_id,)))
        for field, source_id in fixture.source_ids.items()
    }
    before = _read_profile(fixture)
    fixture.declassifications.issue(
        source_id=fixture.source_ids["display_name"], source_session="SA",
        destination_scope="shared.profile.display_name",
        reason="approved identity display", issuer="trusted-reviewer",
    )
    after = _read_profile(fixture)
    after_sources = {
        field: tuple(source.source_id for source in fixture.manager.provenance_registry.lineage((source_id,)))
        for field, source_id in fixture.source_ids.items()
    }
    return MixedFieldExperiment(
        before.value, {key: value.outcome.value for key, value in before.decisions.items()},
        after.value, {key: value.outcome.value for key, value in after.decisions.items()},
        before_sources == after_sources,
        before.restricted_fields_leaked + after.restricted_fields_leaked,
    )


def label_stripping_experiment() -> LabelStrippingExperiment:
    fixture = _base_fixture()
    transaction = fixture.manager.begin("SA")
    fixture.manager.write_shared_object(
        transaction, "stripped", {"private_token": "DEMO-A-SECRET"},
        field_provenance={},
    )
    fixture.manager.validate(transaction); fixture.manager.commit(transaction)
    transaction = fixture.manager.begin("SB")
    result = fixture.manager.read_shared_fields(
        transaction, "stripped", ("private_token",),
        flow_policy=fixture.policy, current_principal=fixture.principal_b,
        destination_scope="shared.stripped",
    )
    fixture.manager.rollback(transaction)
    decision = result.decisions["private_token"]
    return LabelStrippingExperiment(
        True, decision.outcome.value, decision.allowed,
        "private_token" in result.value,
    )


def laundering_experiment() -> LaunderingExperiment:
    fixture = _base_fixture()
    transaction = fixture.manager.begin("SA")
    root = fixture.manager.issue_provenance(
        transaction, RuntimeSourceType.USER_INPUT,
        trust_label=TrustLabel.TRUSTED,
    )
    retrieval = fixture.manager.issue_provenance(
        transaction, RuntimeSourceType.RETRIEVED_CONTENT,
        trust_label=TrustLabel.UNTRUSTED, parent_source_ids=(root.source_id,),
    )
    summary = fixture.manager.issue_provenance(
        transaction, RuntimeSourceType.DERIVED_VALUE,
        trust_label=TrustLabel.UNTRUSTED,
        parent_source_ids=(retrieval.source_id,),
    )
    cache = fixture.manager.issue_provenance(
        transaction, RuntimeSourceType.DERIVED_VALUE,
        trust_label=TrustLabel.UNTRUSTED,
        parent_source_ids=(summary.source_id,),
    )
    fixture.manager.write_shared_object(
        transaction, "laundered", {"summary": "private A content"},
        field_provenance={"summary": (cache.source_id,)},
    )
    fixture.manager.validate(transaction); fixture.manager.commit(transaction)
    transaction_b = fixture.manager.begin("SB")
    result = fixture.manager.read_shared_fields(
        transaction_b, "laundered", ("summary",),
        flow_policy=fixture.policy, current_principal=fixture.principal_b,
        destination_scope="shared.laundered",
    )
    fixture.manager.rollback(transaction_b)
    decision = result.decisions["summary"]
    registry = fixture.manager.provenance_registry
    return LaunderingExperiment(
        (root.source_id, retrieval.source_id, summary.source_id, cache.source_id),
        registry.origin_users((cache.source_id,)),
        registry.origin_sessions((cache.source_id,)),
        registry.origin_transactions((cache.source_id,)),
        decision.outcome.value, decision.allowed, "summary" in result.value,
    )


def run_flow_attack_corpus() -> list[FlowTrial]:
    fixture = _base_fixture()
    trials: list[FlowTrial] = []
    profile = _read_profile(fixture)
    expected = {"display_name": False, "private_token": False, "weather": True}
    for field, decision in profile.decisions.items():
        trials.append(_trial(f"mixed-{field}", "mixed_field_json", field,
                             expected[field], decision))
    for family, source_type in (
        ("committed_shared_state_leakage", RuntimeSourceType.USER_INPUT),
        ("retrieval_cache_contamination", RuntimeSourceType.RETRIEVED_CONTENT),
        ("tool_result_cache_contamination", RuntimeSourceType.TOOL_RESULT),
        ("shared_summary_contamination", RuntimeSourceType.DERIVED_VALUE),
        ("cache_key_collision", RuntimeSourceType.MEMORY),
    ):
        decision = _write_and_attempt(fixture, family, source_type)
        trials.append(_trial(family, family, "restricted", False, decision))
    stripped = label_stripping_experiment()
    trials.append(FlowTrial("label_stripping", "label_stripping", "private_token",
                            False, stripped.allowed, stripped.outcome,
                            stripped.leaked, False))
    laundering = laundering_experiment()
    trials.append(FlowTrial("provenance_laundering", "provenance_laundering", "summary",
                            False, laundering.allowed, laundering.outcome,
                            laundering.leaked, False))
    mixed_decision = _mixed_source_attempt(fixture)
    trials.append(_trial("source_mixing", "source_mixing", "combined", False,
                         mixed_decision))
    # Dirty read is prevented by transaction visibility, not counted as a policy block.
    dirty_prevented = _dirty_read_prevented(fixture)
    trials.append(FlowTrial(
        "dirty_cross_session_read", "dirty_cross_session_read", "role", False,
        False, "TRANSACTION_ISOLATION" if dirty_prevented else "LEAKED",
        not dirty_prevented, False,
    ))
    return trials


def run_concurrency_stress(session_counts: tuple[int, ...] = (10, 25, 50, 100)
                           ) -> list[ConcurrencyResult]:
    return [_concurrent_run(count) for count in session_counts]


def _concurrent_run(count: int) -> ConcurrencyResult:
    if count < 2:
        raise ValueError("concurrency stress requires at least two sessions")
    fixture = _base_fixture()
    fixture.declassifications.issue(
        source_id=fixture.source_ids["display_name"], source_session="SA",
        destination_scope="shared.profile.display_name",
        reason="concurrent approved identity", issuer="trusted-reviewer",
    )
    principals=[];flow_transactions=[];collision_transactions=[]
    fixture.manager.shared_state.apply({"collision": {"seed": 0}}, {"collision": -1})
    for index in range(count):
        session=f"C{index:03d}";user=f"user-{index:03d}"
        fixture.sessions.create_session(session,user_id=user)
        principals.append(SecurityPrincipal(user,session))
        flow_transactions.append(fixture.manager.begin(session))
        collision=fixture.manager.begin(session)
        fixture.manager.read_shared(collision,"collision")
        fixture.manager.write_shared(collision,"collision",{"writer":session})
        fixture.manager.validate(collision)
        collision_transactions.append(collision)
    barrier=threading.Barrier(count);latencies=[];blocked=declassified=public=leaked=false_blocks=0
    metric_lock=threading.Lock()
    def flow_worker(index: int) -> None:
        nonlocal blocked,declassified,public,leaked,false_blocks
        barrier.wait();start=time.perf_counter_ns()
        result=fixture.manager.read_shared_fields(
            flow_transactions[index],"profile",("display_name","private_token","weather"),
            flow_policy=fixture.policy,current_principal=principals[index],
            destination_scope="shared.profile")
        fixture.manager.rollback(flow_transactions[index])
        elapsed=time.perf_counter_ns()-start
        with metric_lock:
            latencies.append(elapsed)
            blocked += int(not result.decisions["private_token"].allowed)
            declassified += int(result.decisions["display_name"].outcome is FlowOutcome.FLOW_DECLASSIFIED)
            public += int(result.decisions["weather"].outcome is FlowOutcome.FLOW_PUBLIC_FIELD_ALLOWED)
            leaked += int(result.decisions["private_token"].allowed)
            false_blocks += int(not result.decisions["weather"].allowed)
    start_all=time.perf_counter_ns()
    with ThreadPoolExecutor(max_workers=count) as executor:
        list(executor.map(flow_worker,range(count)))
    commit_barrier=threading.Barrier(count);conflicts=completed_collisions=0
    def collision_worker(index: int) -> None:
        nonlocal conflicts,completed_collisions
        commit_barrier.wait()
        try: fixture.manager.commit(collision_transactions[index])
        except WriteConflictError:
            with metric_lock: conflicts += 1
        else:
            with metric_lock: completed_collisions += 1
    with ThreadPoolExecutor(max_workers=count) as executor:
        list(executor.map(collision_worker,range(count)))
    elapsed_all=(time.perf_counter_ns()-start_all)/1e9
    ordered=sorted(latencies);p95=ordered[min(len(ordered)-1,max(0,int(.95*len(ordered)+.999)-1))]
    return ConcurrencyResult(
        count,count*2,count+completed_collisions,3*count,blocked,declassified,
        public,leaked,false_blocks,conflicts,all(
            fixture.manager.status(tx).value=="rolled_back" for tx in flow_transactions),
        (count+completed_collisions)/elapsed_all,median(latencies),p95,
    )


def benchmark_flow_overhead(iterations: int = 2000) -> FlowOverheadResult:
    if iterations < 1: raise ValueError("iterations must be positive")
    fixture=_base_fixture();entry=fixture.manager.shared_state.read("profile")
    fields=dict(entry.field_provenance);source=fields["private_token"]
    same=[];denied=[];declassified=[];baseline=[];provenance=[]
    fixture.declassifications.issue(source_id=source[0],source_session="SA",
        destination_scope="bench.declassified",reason="benchmark",issuer="runtime")
    from .flow import FlowResourceScope
    for _ in range(iterations):
        start=time.perf_counter_ns();entry.value["private_token"];baseline.append(time.perf_counter_ns()-start)
        start=time.perf_counter_ns();fields["private_token"];fixture.manager.provenance_registry.labels(source);provenance.append(time.perf_counter_ns()-start)
        start=time.perf_counter_ns();fixture.policy.evaluate(current=fixture.principal_a,scope=FlowResourceScope("profile","bench.same"),source_ids=source);same.append(time.perf_counter_ns()-start)
        start=time.perf_counter_ns();fixture.policy.evaluate(current=fixture.principal_b,scope=FlowResourceScope("profile","bench.denied"),source_ids=source);denied.append(time.perf_counter_ns()-start)
        start=time.perf_counter_ns();fixture.policy.evaluate(current=fixture.principal_b,scope=FlowResourceScope("profile","bench.declassified"),source_ids=source);declassified.append(time.perf_counter_ns()-start)
    return FlowOverheadResult(iterations,median(baseline),median(provenance),median(same),median(denied),median(declassified))


def stage12c_complexity_report(root: Path = Path(".")) -> dict[str,int]:
    source=root/"src"/"transactional_inference_state"
    names=("runtime.py","policy.py","provenance.py","budgets.py","effects.py","operations.py","integrity.py","stage12a.py","cow.py","flow.py")
    paths=[source/name for name in names]
    loc=sum(1 for path in paths for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#"))
    return {"modules":len(paths),"python_loc":loc,"third_party_runtime_dependencies":0,"stage12b_frozen_modules":9,"stage12b_frozen_python_loc":1958}


def _base_fixture() -> _Fixture:
    sessions=SessionManager();sessions.create_session("SA",user_id="A");sessions.create_session("SB",user_id="B");sessions.create_session("PUBLIC",user_id="system")
    manager=TransactionManager(sessions,shared_state=SharedState(),snapshot_strategy=FineGrainedCOWStrategy())
    public_tx=manager.begin("PUBLIC");weather=manager.issue_provenance(public_tx,RuntimeSourceType.SYSTEM_CONTEXT,trust_label=TrustLabel.TRUSTED);manager.validate(public_tx);manager.commit(public_tx)
    tx=manager.begin("SA");display=manager.issue_provenance(tx,RuntimeSourceType.USER_INPUT,trust_label=TrustLabel.TRUSTED);token=manager.issue_provenance(tx,RuntimeSourceType.USER_INPUT,trust_label=TrustLabel.TRUSTED)
    manager.write_shared_object(tx,"profile",{"display_name":"Alice","private_token":"DEMO-A-SECRET","weather":"sunny"},field_provenance={"display_name":(display.source_id,),"private_token":(token.source_id,),"weather":(weather.source_id,)})
    manager.validate(tx);manager.commit(tx)
    declass=DeclassificationRegistry(manager.provenance_registry,manager.event_log)
    return _Fixture(sessions,manager,declass,FlowPolicy(manager.provenance_registry,declass),SecurityPrincipal("A","SA"),SecurityPrincipal("B","SB"),{"display_name":display.source_id,"private_token":token.source_id,"weather":weather.source_id})


def _read_profile(fixture:_Fixture)->FilteredFlowResult:
    tx=fixture.manager.begin("SB");result=fixture.manager.read_shared_fields(tx,"profile",("display_name","private_token","weather"),flow_policy=fixture.policy,current_principal=fixture.principal_b,destination_scope="shared.profile");fixture.manager.rollback(tx);return result


def _trial(identifier:str,family:str,field:str,expected:bool,decision:FlowDecision)->FlowTrial:
    return FlowTrial(identifier,family,field,expected,decision.allowed,decision.outcome.value,(not expected and decision.allowed),(expected and not decision.allowed))


def _write_and_attempt(fixture:_Fixture,family:str,source_type:RuntimeSourceType)->FlowDecision:
    tx=fixture.manager.begin("SA");source=fixture.manager.issue_provenance(tx,source_type,trust_label=TrustLabel.UNTRUSTED);fixture.manager.write_shared_object(tx,family,{"restricted":"A private"},field_provenance={"restricted":(source.source_id,)});fixture.manager.validate(tx);fixture.manager.commit(tx)
    b=fixture.manager.begin("SB");result=fixture.manager.read_shared_fields(b,family,("restricted",),flow_policy=fixture.policy,current_principal=fixture.principal_b,destination_scope=f"shared.{family}");fixture.manager.rollback(b);return result.decisions["restricted"]


def _mixed_source_attempt(fixture:_Fixture)->FlowDecision:
    tx=fixture.manager.begin("SA");private=fixture.manager.issue_provenance(tx,RuntimeSourceType.USER_INPUT,trust_label=TrustLabel.TRUSTED);derived=fixture.manager.issue_provenance(tx,RuntimeSourceType.DERIVED_VALUE,trust_label=TrustLabel.MIXED,parent_source_ids=(private.source_id,fixture.source_ids["weather"]));fixture.manager.write_shared_object(tx,"mixed",{"combined":"mixed"},field_provenance={"combined":(derived.source_id,)});fixture.manager.validate(tx);fixture.manager.commit(tx)
    b=fixture.manager.begin("SB");result=fixture.manager.read_shared_fields(b,"mixed",("combined",),flow_policy=fixture.policy,current_principal=fixture.principal_b,destination_scope="shared.mixed");fixture.manager.rollback(b);return result.decisions["combined"]


def _dirty_read_prevented(fixture:_Fixture)->bool:
    a=fixture.manager.begin("SA");b=fixture.manager.begin("SB");fixture.manager.write_shared(a,"dirty","A-secret")
    try: fixture.manager.read_shared(b,"dirty");observed=True
    except KeyError: observed=False
    fixture.manager.rollback(a);fixture.manager.rollback(b);return not observed
