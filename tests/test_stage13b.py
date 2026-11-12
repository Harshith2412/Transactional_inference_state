import transactional_inference_state as tis


def runtime():
    sessions=tis.SessionManager();sessions.create_session("S",user_id="U")
    graph=tis.LineageGraph();manager=tis.TransactionManager(sessions,snapshot_strategy=tis.FineGrainedCOWStrategy(),lineage_graph=graph)
    tx=manager.begin("S");return sessions,manager,graph,tis.ProvenanceEngine(manager,"S",graph=graph).bind(tx),tx


def test_transform_registry_has_required_trusted_operations():
    registry=tis.TransformRegistry()
    assert set(registry.operations)==set(tis.DataflowOperation)


def test_single_source_propagation_preserves_retrieval_root():
    _,manager,_,engine,tx=runtime();source=engine.source("doc",tis.RuntimeSourceType.RETRIEVED_CONTENT,trust_label=tis.TrustLabel.UNTRUSTED)
    summary=engine.derive(tis.DataflowOperation.SUMMARIZE,[source],"summary")
    assert manager.provenance_registry.origin_sources(summary.source_ids)==source.source_ids
    manager.rollback(tx)


def test_multi_source_propagation_preserves_all_roots():
    _,manager,_,engine,tx=runtime();a=engine.source("a",tis.RuntimeSourceType.RETRIEVED_CONTENT,trust_label=tis.TrustLabel.UNTRUSTED);b=engine.source("b",tis.RuntimeSourceType.RETRIEVED_CONTENT,trust_label=tis.TrustLabel.TRUSTED);u=engine.source("u",tis.RuntimeSourceType.USER_PROMPT,trust_label=tis.TrustLabel.TRUSTED)
    combined=engine.derive(tis.DataflowOperation.CONCAT,[a,b,u],"abu")
    assert set(manager.provenance_registry.origin_sources(combined.source_ids))==set((*a.source_ids,*b.source_ids,*u.source_ids))
    manager.rollback(tx)


def test_field_selection_and_filtering_preserve_only_selected_ancestry():
    _,manager,_,engine,tx=runtime();a=engine.source("a",tis.RuntimeSourceType.SYSTEM_CONTEXT,trust_label=tis.TrustLabel.TRUSTED);b=engine.source("b",tis.RuntimeSourceType.RETRIEVED_CONTENT,trust_label=tis.TrustLabel.UNTRUSTED)
    obj=engine.build_context({"public":a,"private":b});selected=engine.select_field(obj,"public");filtered=engine.filter_fields(obj,("public",))
    assert manager.provenance_registry.origin_sources(selected.source_ids)==a.source_ids
    assert filtered.field_sources["public"]==a.source_ids and "private" not in filtered.field_sources
    manager.rollback(tx)


def test_memory_write_and_later_read_retain_original_ancestry():
    _,manager,_,engine,tx=runtime();source=engine.source("poison",tis.RuntimeSourceType.RETRIEVED_CONTENT,trust_label=tis.TrustLabel.UNTRUSTED);path=tis.FieldPath.keys("session_memory","x");engine.write_memory(path,source);manager.validate(tx);manager.commit(tx)
    tx2=manager.begin("S");engine.bind(tx2);read=engine.read_memory(path)
    assert manager.provenance_registry.origin_sources(read.source_ids)==source.source_ids
    manager.rollback(tx2)


def test_cache_write_and_later_reuse_retain_original_ancestry():
    _,manager,_,engine,tx=runtime();source=engine.source("poison",tis.RuntimeSourceType.RETRIEVED_CONTENT,trust_label=tis.TrustLabel.UNTRUSTED);path=tis.FieldPath.keys("application_cache","x");engine.write_cache(path,source);manager.validate(tx);manager.commit(tx)
    tx2=manager.begin("S");engine.bind(tx2);read=engine.read_cache(path);context=engine.build_context({"cache":read})
    assert manager.provenance_registry.origin_sources(context.source_ids)==source.source_ids
    manager.rollback(tx2)


def test_tool_result_includes_tool_node_and_input_ancestry():
    _,manager,graph,engine,tx=runtime();source=engine.source("project",tis.RuntimeSourceType.USER_PROMPT,trust_label=tis.TrustLabel.TRUSTED);result=engine.tool_call("status",[source],{"status":"ok"})
    assert manager.provenance_registry.origin_sources(result.source_ids)==source.source_ids
    assert graph.get(result.node_id).node_type is tis.LineageNodeType.TOOL_RESULT
    manager.rollback(tx)


def test_context_assembly_retains_segment_level_provenance():
    _,_,_,engine,tx=runtime();a=engine.source("request",tis.RuntimeSourceType.USER_PROMPT,trust_label=tis.TrustLabel.TRUSTED);b=engine.source("doc",tis.RuntimeSourceType.RETRIEVED_CONTENT,trust_label=tis.TrustLabel.UNTRUSTED);ctx=engine.build_context({"request":a,"document":b})
    assert ctx.field_sources=={"request":a.source_ids,"document":b.source_ids}
    engine.manager.rollback(tx)


def test_effect_arguments_propagate_without_execution_before_commit():
    sessions=tis.SessionManager();sessions.create_session("S",user_id="U");service=tis.FakeEmailService();effects=tis.EffectManager(service);graph=tis.LineageGraph();manager=tis.TransactionManager(sessions,snapshot_strategy=tis.FineGrainedCOWStrategy(),effect_manager=effects,lineage_graph=graph);tx=manager.begin("S");engine=tis.ProvenanceEngine(manager,"S",graph=graph).bind(tx)
    subject=engine.source("subject",tis.RuntimeSourceType.USER_PROMPT,trust_label=tis.TrustLabel.TRUSTED);body=engine.source("body",tis.RuntimeSourceType.RETRIEVED_CONTENT,trust_label=tis.TrustLabel.UNTRUSTED);effect,value=engine.stage_email(to="friend@example.test",subject=subject,body=body)
    assert not service.sent_messages and set(manager.provenance_registry.origin_sources(value.source_ids))==set((*subject.source_ids,*body.source_ids))
    manager.rollback(tx)


def test_field_level_independence_avoids_taint_explosion():
    result=tis.field_precision_experiment()
    assert result["precision"]==1 and result["recall"]==1
    assert result["false_lineage_count"]==0 and not result["selected_public_has_untrusted_ancestor"]


def test_declassification_changes_permission_not_origin():
    sessions,manager,_,engine,tx=runtime();source=engine.source("A",tis.RuntimeSourceType.USER_PROMPT,trust_label=tis.TrustLabel.TRUSTED);manager.validate(tx);manager.commit(tx)
    rules=tis.DeclassificationRegistry(manager.provenance_registry,manager.event_log);rules.issue(source_id=source.source_ids[0],source_session="S",destination_scope="shared.x",reason="reviewed",issuer="reviewer")
    assert manager.provenance_registry.origin_sessions(source.source_ids)==("S",)


def test_missing_instrumentation_fails_closed_and_records_gap():
    result=tis.provenance_gap_experiment()
    assert not result["verified"] and result["gap_count"]==1 and result["event_recorded"]


def test_manual_and_automatic_root_attribution_are_equivalent():
    result=tis.manual_vs_automatic_comparison()
    assert result["manual"]["correct_root_attribution"] and result["automatic"]["correct_root_attribution"]
    assert result["manual"]["explicit_application_lineage_calls"]>result["automatic"]["explicit_application_lineage_calls"]


def test_cache_poison_root_attribution_reaches_t1_source():
    result=tis.automatic_cache_poison_flagship()
    assert all(result[x] for x in ("correct_origin_user","correct_origin_session","correct_origin_transaction","correct_origin_source"))
    assert result["persistent_compromise"] and not result["effect_executed"]


def test_memory_poison_root_attribution_and_recovery():
    result=tis.automatic_memory_poison_flagship()
    assert all(result[x] for x in ("correct_origin_user","correct_origin_session","correct_origin_transaction","correct_origin_source"))
    assert result["recovery_result"]["invalidated_ids"]


def test_automatic_corpus_preserves_stage13a_security_metrics_and_full_coverage():
    result=tis.run_automatic_agent_corpus()
    assert result["security_summary"]["policy_detection"]=={"count":9,"denominator":20}
    assert result["security_summary"]["persistent_compromise"]=={"count":11,"denominator":20}
    assert result["coverage"]=={"authoritative":40,"denominator":40,"mean":1.0,"unknown_rate":0.0}


def test_complexity_adds_one_small_trusted_module_without_dependencies():
    result=tis.stage13b_complexity_report()
    assert result["trusted_core_modules"]==13 and result["trusted_core_growth_modules"]==1
    assert result["automatic_propagation_trusted_loc"]==result["trusted_core_growth_loc"]
    assert result["third_party_runtime_dependencies"]==0


def test_stage13b_artifacts_have_ten_tables_and_eight_figures(tmp_path):
    document=tis.stage13b_evaluation_document()
    tis.generate_stage13b_artifacts(document,tmp_path)
    assert len(tuple((tmp_path/"tables").glob("*.csv")))==10
    assert len(tuple((tmp_path/"figures").glob("*.svg")))==8


def test_policy_fingerprints_remain_frozen_stage13b():
    assert tis.policy_fingerprint(tis.PolicyV1())=="b9c476b30befcd7ae7a34c0effaee6f991cc84d76d64154d56ee95aba460ffb7"
    assert tis.policy_fingerprint(tis.PolicyV2())=="ca3702e69066389a46b785e067ad068d34a6401828d0dfc933523216a386962e"
