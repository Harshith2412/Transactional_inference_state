import json
import transactional_inference_state as tis


def test_external_adapter_inventory_and_selection():
    tasks=tis.external_tasks()
    assert len(tasks)==40 and sum(x.malicious for x in tasks)==20
    assert {x.benchmark for x in tasks}=={tis.BenchmarkFamily.ASB_MEMORY,tis.BenchmarkFamily.AGENTDOJO}


def test_manifest_is_canonical_and_frozen():
    document=tis.manifest_document();digest=tis.manifest_hash(document)
    assert len(digest)==64 and digest==tis.manifest_hash()
    assert document["frozen_before_evaluation"] is True
    assert {x["commit"] for x in document["benchmarks"]}=={tis.ASB_COMMIT,tis.AGENTDOJO_COMMIT}


def test_ground_truth_is_not_present_in_validator_evidence():
    evidence=tis.adapter_evidence(next(x for x in tis.external_tasks() if x.malicious))
    assert not hasattr(evidence,"malicious") and not hasattr(evidence,"attack_type")


def test_memory_lifecycle_remains_multiphase():
    primary=tuple(x for x in tis.external_tasks() if x.benchmark is tis.BenchmarkFamily.ASB_MEMORY)
    result=tis.evaluate_memory_lifecycle(primary)
    row=next(x for x in result["trials"] if x["malicious"] and x["validator"]=="POLICY_V2_BASELINE")
    assert row["malicious_write_proposed"] and row["memory_persisted"]
    assert row["poison_retrieved"] and row["poison_influences_context"]


def test_adaptation_and_unsupported_task_log_are_explicit():
    assert all(x.adaptation_notes for x in tis.external_tasks())
    assert len(tis.excluded_tasks())>=4
    assert all(set(x)=={"task_id","reason"} for x in tis.excluded_tasks())


def test_adapter_only_provenance_transforms_are_not_silently_clean():
    result=tis.provenance_analysis(tis.external_tasks())
    assert result["classification"]["ADAPTER_ONLY_TRANSFORM"]>0
    assert result["provenance_coverage"]<1 and result["gap_rate"]>0


def test_forced_rejection_contains_external_state_and_effects():
    result=tis.forced_rejection_experiment(tis.external_tasks())
    assert result["contained"]==result["denominator"]==20
    assert all(x["rollback_integrity"] and not x["transactional_external_effect"] for x in result["trials"])


def test_external_recovery_uses_causal_ground_truth_and_preserves_unrelated_state():
    result=tis.evaluate_stage14a()["recovery"]
    assert result["cases_with_causal_ground_truth"]==10
    assert result["origin_correct"]==result["contaminated_state_identified"]==10
    assert result["unrelated_preserved"]==result["post_recovery_reuse_blocked"]==10


def test_external_metric_aggregation_has_exact_denominators():
    result=tis.evaluate_validators(tis.external_tasks())
    for metric in result["metrics"].values():
        assert metric["tp"]+metric["fn"]==20
        assert metric["fp"]+metric["tn"]==20


def test_artifact_generator_freezes_manifest_before_results(tmp_path):
    result=tis.generate_stage14a_artifacts(tmp_path)
    manifest=json.loads((tmp_path/"corpus/external_manifest.json").read_text())
    assert (tmp_path/"corpus/external_manifest.sha256").read_text().strip()==tis.manifest_hash(manifest)==result["manifest_hash"]
    assert len(list((tmp_path/"tables").iterdir()))==10
    assert len(list((tmp_path/"figures").iterdir()))==8
