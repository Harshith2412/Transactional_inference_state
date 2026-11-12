import dataclasses

import transactional_inference_state as tis
from transactional_inference_state.stage13c import _evidence


def heldout(family,malicious=True):
    return next(x for x in tis.stage13c_heldout_corpus() if x.attack_family==family and x.malicious==malicious)


def test_common_validator_interface_returns_inspectable_decision():
    decision=tis.PolicyV2BaselineValidator().evaluate(_evidence(heldout("semantic_poisoning")))
    assert isinstance(decision,tis.ValidatorDecision) and decision.validator_name
    assert decision.action in set(tis.ValidatorAction) and decision.reasons


def test_policy_v2_adapter_reproduces_stage13a_baseline():
    result=tis.evaluate_stage13c_corpus(tis.stage13c_development_corpus(),(tis.PolicyV2BaselineValidator(),))
    assert result["metrics"]["POLICY_V2_BASELINE"]["tp"]==9
    assert result["metrics"]["POLICY_V2_BASELINE"]["fp"]==0


def test_sequence_validator_detects_ordered_write_effect_risk():
    decision=tis.SequenceAwareAgentValidator().evaluate(_evidence(heldout("sequence_abuse")))
    assert decision.action is tis.ValidatorAction.DENY
    assert "RISKY_OPERATION_SEQUENCE" in decision.reasons


def test_provenance_validator_uses_authoritative_untrusted_ancestry():
    decision=tis.ProvenanceAwareAgentValidator().evaluate(_evidence(heldout("retrieval_poisoning")))
    assert decision.action is tis.ValidatorAction.QUARANTINE
    assert "UNTRUSTED_ANCESTRY" in decision.reasons


def test_semantic_validator_detects_preselected_poisoning_case():
    decision=tis.SemanticRuleAgentValidator().evaluate(_evidence(heldout("semantic_poisoning")))
    assert decision.action is tis.ValidatorAction.DENY
    assert "SEMANTIC_PRIOR_AUTHORIZATION_CLAIM" in decision.reasons


def test_hybrid_uses_explicit_deny_overrides_composition():
    decision=tis.HybridDeterministicValidator().evaluate(_evidence(heldout("semantic_poisoning")))
    assert decision.action is tis.ValidatorAction.DENY
    assert any(x.startswith("SEMANTIC_RULE:") for x in decision.reasons)


def test_validator_disagreement_is_retained_with_reasons():
    result=tis.evaluate_stage13c_corpus((heldout("semantic_poisoning"),))
    disagreements=tis.stage13c_disagreement_analysis(result)
    assert disagreements["rows"]
    assert all(x["left_reasons"] and x["right_reasons"] for x in disagreements["rows"])


def test_heldout_corpus_and_validator_configuration_are_frozen():
    assert len(tis.stage13c_development_corpus())==40 and len(tis.stage13c_heldout_corpus())==40
    assert tis.stage13c_heldout_freeze_hash()=="186dd355060a46ae9c83b7da0e8f2c484d9e4ab9be767ba317ebb1be9f79ddc3"
    assert tis.validator_fingerprints()["SEMANTIC_RULE"]=="3623808590f95dfbc16245ea29842fc69a6dd0e5e494a88c72cff51df617f82c"


def test_all_validator_fingerprints_have_sha256_shape():
    fingerprints=tis.validator_fingerprints()
    assert set(fingerprints)=={"POLICY_V2_BASELINE","SEQUENCE_AWARE","PROVENANCE_AWARE","SEMANTIC_RULE","HYBRID_DETERMINISTIC"}
    assert all(len(x)==64 for x in fingerprints.values())


def test_hard_benign_semantic_language_is_not_rejected_by_semantic_validator():
    scenario=heldout("hard_benign",False)
    decision=tis.SemanticRuleAgentValidator().evaluate(_evidence(scenario))
    assert decision.action is tis.ValidatorAction.ALLOW
    assert "BENIGN_CONTEXT_FRAME" in decision.reasons


def test_same_text_has_different_provenance_outcome():
    untrusted=heldout("semantic_poisoning");trusted=dataclasses.replace(untrusted,source_type=tis.RuntimeSourceType.SYSTEM_CONTEXT,trust_label=tis.TrustLabel.TRUSTED)
    validator=tis.ProvenanceAwareAgentValidator()
    assert validator.evaluate(_evidence(untrusted)).action is tis.ValidatorAction.QUARANTINE
    assert validator.evaluate(_evidence(trusted)).action is tis.ValidatorAction.ALLOW


def test_provenance_gap_requires_review():
    scenario=next(x for x in tis.stage13c_heldout_corpus() if x.provenance_gap)
    decision=tis.ProvenanceAwareAgentValidator().evaluate(_evidence(scenario))
    assert decision.action is tis.ValidatorAction.REVIEW


def test_latency_schema_covers_every_validator():
    result=tis.evaluate_stage13c_corpus(tis.stage13c_heldout_corpus())
    assert set(result["latency"])==set(result["validators"])
    assert all(set(x)=={"median_ns","p95_ns"} and x["median_ns"]>0 for x in result["latency"].values())


def test_optional_ml_validator_is_explicitly_unavailable_and_outside_core():
    assert not tis.OptionalMLValidator.available
    assert "third-party" in tis.OptionalMLValidator.reason


def test_optional_llm_judge_is_unavailable_advisory_not_trusted():
    assert not tis.OptionalLLMJudgeValidator.available and tis.OptionalLLMJudgeValidator.advisory


def test_heldout_metrics_expose_recall_false_positive_tradeoff():
    result=tis.evaluate_stage13c_corpus(tis.stage13c_heldout_corpus())
    assert result["metrics"]["POLICY_V2_BASELINE"]["recall"]==.4
    assert result["metrics"]["SEMANTIC_RULE"]["recall"]==.5
    assert result["metrics"]["HYBRID_DETERMINISTIC"]["recall"]==1
    assert result["metrics"]["HYBRID_DETERMINISTIC"]["fpr"]==.5


def test_policy_fingerprints_unchanged_stage13c():
    assert tis.policy_fingerprint(tis.PolicyV1())=="b9c476b30befcd7ae7a34c0effaee6f991cc84d76d64154d56ee95aba460ffb7"
    assert tis.policy_fingerprint(tis.PolicyV2())=="ca3702e69066389a46b785e067ad068d34a6401828d0dfc933523216a386962e"


def test_stage13c_artifact_generator_writes_required_outputs(tmp_path):
    document=tis.stage13c_evaluation_document()
    tis.generate_stage13c_artifacts(document,tmp_path)
    assert len(tuple((tmp_path/"tables").glob("*.csv")))==10
    assert len(tuple((tmp_path/"figures").glob("*.svg")))==8
