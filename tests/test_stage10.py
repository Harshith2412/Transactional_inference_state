import json
from pathlib import Path
import pytest
import transactional_inference_state as tis
from transactional_inference_state.stage10_reporting import generate_stage10_artifacts

def test_generation_configuration_and_prompt_versioning():
    c=tis.GenerationConfiguration("model",tis.StructuredGenerationMode.EXPLICIT_SCHEMA)
    assert c.temperature==0 and c.seed==0 and c.prompt_hash==tis.MODEL_PLAN_PROMPT_HASH
    assert "propose operations" in tis.generation_prompt(c.mode,"remember x")

@pytest.mark.parametrize("raw,error,expected",[
 ("","malformed",tis.ParseFailureCategory.EMPTY_OUTPUT),
 ("```json\n{}\n```","x",tis.ParseFailureCategory.MARKDOWN_WRAPPER),
 ("Here: {}","x",tis.ParseFailureCategory.PROSE_AROUND_JSON),
 ("{","malformed model output",tis.ParseFailureCategory.TRUNCATED_OUTPUT),
 ("nope","malformed model output",tis.ParseFailureCategory.INVALID_JSON),
 ("{}","unknown operation type",tis.ParseFailureCategory.UNKNOWN_OPERATION),
 ("{}","unsupported provenance",tis.ParseFailureCategory.INVALID_PROVENANCE),
 ("{}","duplicate operation_id",tis.ParseFailureCategory.DUPLICATE_OPERATION_ID),
])
def test_parse_failure_classification(raw,error,expected):
    assert tis.classify_parse_failure(raw,error)==expected

def test_timeout_classification_has_priority():
    assert tis.classify_parse_failure("", "", timed_out=True) is tis.ParseFailureCategory.TIMEOUT

def test_new_malicious_heldout_is_balanced_and_distinct():
    rows=tis.stage10_malicious_heldout(); assert len(rows)==100
    counts={f:sum(x.scenario.attack_family==f for x in rows) for f in tis.ATTACK_FAMILIES}
    assert min(counts.values())>=7 and max(counts.values())<=8
    assert not {x.scenario.scenario_id for x in rows}&{x.scenario_id for x in tis.adversarial_split("held_out")}

def test_new_hard_benign_heldout_validation():
    rows=tis.stage10_benign_heldout(); assert len(rows)==80
    assert all(not x.scenario.malicious and x.split=="stage10_held_out" for x in rows)

def test_frozen_manifest_is_stable_and_unique():
    assert tis.frozen_live_subset()==tis.frozen_live_subset()
    assert len(tis.frozen_live_subset())==len(set(tis.frozen_live_subset()))==50

def test_native_mode_is_optional_generation_aid():
    config=tis.GenerationConfiguration("local",tis.StructuredGenerationMode.NATIVE_SCHEMA)
    assert config.mode.value=="native_schema" and tis.MODEL_PLAN_SCHEMA["additionalProperties"] is False

def test_same_plan_compared_under_both_frozen_policies():
    results=tis.run_deterministic_validation()
    assert [x.policy for x in results]==["policy_v1","policy_v2"]
    assert [t.scenario_id for t in results[0].trials]==[t.scenario_id for t in results[1].trials]

def test_na_denominator_behavior():
    assert tis.nullable_rate(0,0) is None and tis.nullable_rate(1,2)==.5

def test_latency_aggregation_schema_and_percentiles():
    x=tis.aggregate_latency([1,2,3,4,100]); assert x.count==5 and x.mean==22 and x.p95==100
    assert tis.aggregate_latency([]).mean is None

def test_complexity_and_dependency_audit():
    r=tis.complexity_report(Path(".")); assert r["trusted_core"]["external_runtime_dependencies"]==0
    assert r["dependency_audit"]["large_agent_frameworks"]==[]

def test_model_adapter_records_generation_controls():
    adapter=tis.OllamaModelAdapter("x",temperature=0,seed=7,top_p=.8,
        maximum_output_tokens=100,native_schema=tis.MODEL_PLAN_SCHEMA)
    assert adapter.seed==7 and adapter.native_schema==tis.MODEL_PLAN_SCHEMA

def test_stage10_reporting_generates_ten_tables_twelve_figures(tmp_path):
    deterministic=tis.run_deterministic_validation(); complexity=tis.complexity_report(Path("."))
    paths=generate_stage10_artifacts(deterministic=deterministic,stage9_metrics={},
      reliability=[],security=[],failures=[],multi_turn=[],latency=[],live_false_negatives=[],
      complexity=complexity,output_dir=tmp_path)
    assert len(paths)==22 and all(p.exists() for p in paths)

def test_stage10_policy_v2_is_not_perfect_on_new_frozen_set():
    v2=tis.run_deterministic_validation()[1]
    assert v2.confusion.fn>0 and v2.confusion.fp>0

def test_strict_parser_still_rejects_extra_root_field():
    with pytest.raises(tis.ModelPlanError):
        tis.parse_model_plan(json.dumps({"operations":[],"final_response":"x","extra":1}))
