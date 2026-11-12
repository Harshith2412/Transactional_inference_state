import pytest

import transactional_inference_state as tis
from transactional_inference_state import stage12c


def chain_graph():
    graph = tis.LineageGraph()
    graph.add_node(tis.LineageNode("source", tis.LineageNodeType.RETRIEVAL,
        "U", "S", "T1", "source", tis.TrustLabel.UNTRUSTED))
    graph.add_node(tis.LineageNode("memory", tis.LineageNodeType.MEMORY,
        "U", "S", "T1", "derived", tis.TrustLabel.MIXED))
    graph.add_node(tis.LineageNode("effect", tis.LineageNodeType.EFFECT,
        "U", "S", "T8", "effect-source", tis.TrustLabel.MIXED))
    graph.add_edge("source", "memory"); graph.add_edge("memory", "effect")
    return graph


def test_lineage_ancestor_descendant_and_origin_queries():
    graph = chain_graph()
    assert tuple(x.node_id for x in graph.ancestors("effect")) == ("memory", "source")
    assert tuple(x.node_id for x in graph.descendants("source")) == ("memory", "effect")
    assert graph.origin_users("effect") == ("U",)
    assert graph.origin_sessions("effect") == ("S",)
    assert graph.origin_transactions("effect") == ("T1",)
    assert graph.origin_sources("effect") == ("source",)
    assert graph.first_untrusted_ancestor("effect").node_id == "source"


def test_multiple_parents_and_source_mixing_preserve_every_origin():
    graph = tis.LineageGraph()
    roots = (("public", "public-user", "public-session", tis.TrustLabel.TRUSTED),
             ("private-A", "A", "SA", tis.TrustLabel.UNTRUSTED),
             ("system", "system", "system-session", tis.TrustLabel.TRUSTED))
    for node, user, session, trust in roots:
        graph.add_node(tis.LineageNode(node, tis.LineageNodeType.USER_INPUT,
            user, session, f"tx-{node}", node, trust))
    graph.add_node(tis.LineageNode("mixed", tis.LineageNodeType.MODEL_OUTPUT))
    for node, *_ in roots: graph.add_edge(node, "mixed")
    assert graph.origin_sources("mixed") == ("private-A", "public", "system")
    assert graph.origin_sessions("mixed") == ("SA", "public-session", "system-session")
    report = graph.analyze_contamination("mixed")
    assert "private-A" in report.upstream_untrusted_ids
    assert "public" not in report.upstream_untrusted_ids


@pytest.mark.parametrize("nodes", [
    ("untrusted", "summary", "renamed", "cache", "copied-memory", "effect"),
    ("original-text", "paraphrased-summary", "effect"),
    ("plaintext", "encoded-like", "decoded-like", "effect"),
    ("tool-result", "memory", "cache", "effect"),
])
def test_representation_changes_do_not_strip_explicit_lineage(nodes):
    graph = tis.LineageGraph()
    source_type = (tis.LineageNodeType.TOOL_RESULT if nodes[0] == "tool-result"
                   else tis.LineageNodeType.RETRIEVAL)
    graph.add_node(tis.LineageNode(nodes[0], source_type, "U", "S", "T1",
        nodes[0], tis.TrustLabel.UNTRUSTED))
    for parent, child in zip(nodes, nodes[1:]):
        kind = tis.LineageNodeType.EFFECT if child == "effect" else tis.LineageNodeType.SUMMARY
        graph.add_node(tis.LineageNode(child, kind, trust_label=tis.TrustLabel.MIXED))
        graph.add_edge(parent, child)
    assert graph.origin_sources(nodes[-1]) == (nodes[0],)
    assert graph.first_untrusted_ancestor(nodes[-1]).node_id == nodes[0]


def test_missing_lineage_is_unverified_and_conservative():
    graph = tis.LineageGraph()
    graph.add_node(tis.LineageNode("stripped", tis.LineageNodeType.MODEL_OUTPUT,
        trust_label=tis.TrustLabel.UNKNOWN, verified_lineage=False))
    graph.add_node(tis.LineageNode("effect", tis.LineageNodeType.EFFECT))
    graph.add_edge("stripped", "effect")
    assert graph.first_untrusted_ancestor("effect").node_id == "stripped"


def test_contamination_detects_branch_descendants_but_not_unrelated_roots():
    graph = chain_graph()
    graph.add_node(tis.LineageNode("later-cache", tis.LineageNodeType.CACHE))
    graph.add_edge("memory", "later-cache")
    graph.add_node(tis.LineageNode("unrelated", tis.LineageNodeType.MEMORY,
                                  trust_label=tis.TrustLabel.TRUSTED))
    report = graph.analyze_contamination("effect")
    assert set(report.contaminated_node_ids) == {"source", "memory", "effect", "later-cache"}
    assert "unrelated" in report.unrelated_committed_ids


def test_selective_recovery_blocks_ordinary_reads_and_preserves_unrelated_state():
    sessions = tis.SessionManager(); state = sessions.create_session("S")
    state.session_memory = {"bad": "poison", "good": "keep"}
    graph = tis.LineageGraph()
    bad = tis.FieldPath.keys("session_memory", "bad")
    good = tis.FieldPath.keys("session_memory", "good")
    graph.add_node(tis.LineageNode("source", tis.LineageNodeType.RETRIEVAL,
        "U", "S", "T1", "source", tis.TrustLabel.UNTRUSTED))
    graph.add_node(tis.LineageNode("bad", tis.LineageNodeType.MEMORY,
        "U", "S", "T1", "source", tis.TrustLabel.MIXED,
        tis.StateReference("S", bad)))
    graph.add_node(tis.LineageNode("good", tis.LineageNodeType.MEMORY,
        "U", "S", "T2", "good-source", tis.TrustLabel.TRUSTED,
        tis.StateReference("S", good)))
    graph.add_node(tis.LineageNode("effect", tis.LineageNodeType.EFFECT))
    graph.add_edge("source", "bad"); graph.add_edge("bad", "effect")
    report = graph.analyze_contamination("effect"); plan = graph.create_recovery_plan(report)
    result = graph.apply_recovery(plan, sessions)
    manager = tis.TransactionManager(sessions, snapshot_strategy=tis.FineGrainedCOWStrategy(),
                                     lineage_graph=graph)
    tx = manager.begin("S")
    with pytest.raises(tis.TransactionError, match="not readable"):
        manager.read_path(tx, "S", bad)
    assert manager.read_path(tx, "S", good) == "keep"
    manager.rollback(tx)
    assert result.quarantined_ids == ("bad",)
    assert graph.trusted_quarantine("bad").value == "poison"


def test_stale_recovery_plan_is_rejected_and_audit_is_append_only():
    graph = chain_graph(); report = graph.analyze_contamination("effect")
    plan = graph.create_recovery_plan(report)
    graph.add_node(tis.LineageNode("new", tis.LineageNodeType.MEMORY))
    sessions = tis.SessionManager(); sessions.create_session("S")
    with pytest.raises(tis.TransactionError, match="stale recovery"):
        graph.apply_recovery(plan, sessions)
    assert [x.event_type for x in graph.event_log.events] == [
        "CONTAMINATION_IDENTIFIED", "RECOVERY_PLAN_CREATED"]


def test_flagship_has_eight_transactions_correct_attribution_and_recovery():
    result = tis.run_delayed_compromise_flagship()
    assert len(set(result["transaction_ids"].values())) == 8
    assert result["origin"]["transactions"] == (result["transaction_ids"]["T1"],)
    assert result["origin"]["sessions"] == ("SA",)
    assert result["origin"]["users"] == ("A",)
    assert result["root_untrusted_source"] == result["origin"]["sources"][0]
    assert result["effect_executed"] is False
    assert result["unrelated_state_preserved"]
    assert result["post_recovery_reads_blocked"] == 3
    assert result["post_recovery_leakage"] == 0


def test_delayed_corpus_exact_denominators_and_metrics():
    result = tis.run_delayed_attack_corpus(); summary = result["summary"]
    assert summary["delayed_attack_count"] == 25
    assert summary["denominators"] == {
        "attacks": 25, "contaminated_nodes": 365, "unrelated_nodes": 50}
    assert summary["correct_origin_transaction"] == 25
    assert summary["contamination_precision"] == 1
    assert summary["contamination_recall"] == 1
    assert summary["over_quarantine_rate"] == 0
    assert summary["under_recovery_rate"] == 0


def test_cross_session_delayed_ancestry_remains_session_a_after_allowed_transfer():
    fixture = stage12c._base_fixture()
    fixture.declassifications.issue(
        source_id=fixture.source_ids["private_token"], source_session="SA",
        destination_scope="shared.delayed.private_token",
        reason="explicit controlled Stage 12E transfer", issuer="reviewer")
    flow = fixture.policy.evaluate(
        current=fixture.principal_b,
        scope=tis.FlowResourceScope("delayed", "shared.delayed.private_token"),
        source_ids=(fixture.source_ids["private_token"],))
    assert flow.allowed and flow.outcome is tis.FlowOutcome.FLOW_DECLASSIFIED
    graph = tis.LineageGraph()
    graph.add_node(tis.LineageNode("A-private", tis.LineageNodeType.MEMORY,
        "A", "SA", "TA", fixture.source_ids["private_token"], tis.TrustLabel.UNTRUSTED))
    graph.add_node(tis.LineageNode("declassified", tis.LineageNodeType.SHARED_STATE,
        "A", "SA", "TD", trust_label=tis.TrustLabel.MIXED,
        metadata={"declassified": True}))
    graph.add_node(tis.LineageNode("B-memory", tis.LineageNodeType.MEMORY,
        "B", "SB", "TB", trust_label=tis.TrustLabel.MIXED))
    graph.add_node(tis.LineageNode("effect", tis.LineageNodeType.EFFECT,
                                  "B", "SB", "TE"))
    graph.add_edge("A-private", "declassified"); graph.add_edge("declassified", "B-memory")
    graph.add_edge("B-memory", "effect")
    assert graph.origin_sessions("effect") == ("SA",)
    assert graph.first_untrusted_ancestor("effect").node_id == "A-private"


def test_stage12d_quarantine_cannot_reenter_normal_lineage_reads():
    sessions = tis.SessionManager(); state = sessions.create_session("S", user_id="U")
    manager = tis.TransactionManager(sessions, snapshot_strategy=tis.FineGrainedCOWStrategy())
    resolver = tis.SelectiveTransactionResolver(manager); path = tis.FieldPath.keys("session_memory", "q")
    tx = manager.begin("S"); source = manager.issue_provenance(
        tx, tis.RuntimeSourceType.RETRIEVED_CONTENT, trust_label=tis.TrustLabel.UNTRUSTED)
    manager.write_path(tx, "S", path, "hidden", provenance_ids=(source.source_id,))
    resolver.resolve(tx, tis.ValidationDecision(tis.DecisionAction.QUARANTINE))
    assert "q" not in state.session_memory
    assert resolver.quarantine.list_for_transaction(tx)[0].value == "hidden"


def test_selective_commit_registers_only_normal_durable_branch_in_later_lineage():
    sessions = tis.SessionManager(); state = sessions.create_session("S", user_id="U")
    manager = tis.TransactionManager(sessions, snapshot_strategy=tis.FineGrainedCOWStrategy())
    resolver = tis.SelectiveTransactionResolver(manager)
    safe_path = tis.FieldPath.keys("session_memory", "safe")
    bad_path = tis.FieldPath.keys("session_memory", "bad")
    tx = manager.begin("S")
    safe_source = manager.issue_provenance(tx, tis.RuntimeSourceType.USER_INPUT,
                                           trust_label=tis.TrustLabel.TRUSTED)
    bad_source = manager.issue_provenance(tx, tis.RuntimeSourceType.RETRIEVED_CONTENT,
                                          trust_label=tis.TrustLabel.UNTRUSTED)
    manager.write_path(tx, "S", safe_path, "keep", provenance_ids=(safe_source.source_id,))
    manager.write_path(tx, "S", bad_path, "poison", provenance_ids=(bad_source.source_id,))
    resolver.resolve(tx, tis.ValidationDecision(tis.DecisionAction.SELECTIVE_COMMIT,
        field_decisions=(tis.FieldDecision(safe_path, tis.DecisionAction.COMMIT, "safe",
                         provenance_ids=(safe_source.source_id,)),
                         tis.FieldDecision(bad_path, tis.DecisionAction.QUARANTINE, "unsafe",
                         provenance_ids=(bad_source.source_id,)))))
    graph = tis.LineageGraph()
    graph.add_node(tis.LineageNode("safe", tis.LineageNodeType.MEMORY,
        "U", "S", tx, safe_source.source_id, tis.TrustLabel.TRUSTED,
        tis.StateReference("S", safe_path)))
    assert state.session_memory == {"safe": "keep"}
    assert {node.node_id for node in graph.nodes} == {"safe"}


def test_graph_growth_accounting_and_no_unproven_compaction():
    result = tis.run_graph_growth_experiment(iterations=1)
    assert [row["nodes"] for row in result["rows"]] == [100, 1000, 10000]
    assert [row["edges"] for row in result["rows"]] == [99, 999, 9999]
    assert result["rows"][2]["estimated_bytes"] > result["rows"][0]["estimated_bytes"]
    assert result["compaction"]["implemented"] is False


def test_policy_fingerprints_unchanged_stage12e():
    assert tis.policy_fingerprint(tis.PolicyV1()) == "b9c476b30befcd7ae7a34c0effaee6f991cc84d76d64154d56ee95aba460ffb7"
    assert tis.policy_fingerprint(tis.PolicyV2()) == "ca3702e69066389a46b785e067ad068d34a6401828d0dfc933523216a386962e"
