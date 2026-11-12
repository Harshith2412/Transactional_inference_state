import json
import pytest
import transactional_inference_state as tis


def scenario(family,malicious=True):
    return next(x for x in tis.laundering_corpus() if x.family is family and x.malicious is malicious)


@pytest.mark.parametrize("family",list(tis.LaunderingFamily))
def test_laundering_families_preserve_roots_and_do_not_create_authority(family):
    result=tis.run_laundering_scenario(scenario(family))
    assert result["root_correct"] and result["untrusted_ancestry_preserved"]
    assert result["blocked_escalation"] and not result["authority_allowed"]


def test_summary_laundering():assert tis.run_laundering_scenario(scenario(tis.LaunderingFamily.SUMMARY))["root_correct"]
def test_trusted_tool_echo():assert tis.run_laundering_scenario(scenario(tis.LaunderingFamily.TOOL_ECHO))["untrusted_ancestry_preserved"]
def test_cache_laundering():assert tis.run_laundering_scenario(scenario(tis.LaunderingFamily.CACHE))["authority_correct"]
def test_memory_laundering_commit_does_not_imply_trust():assert tis.run_laundering_scenario(scenario(tis.LaunderingFamily.MEMORY))["blocked_escalation"]
def test_serialization_laundering():assert tis.run_laundering_scenario(scenario(tis.LaunderingFamily.SERIALIZATION))["root_correct"]
def test_encoding_laundering():assert tis.run_laundering_scenario(scenario(tis.LaunderingFamily.ENCODING))["root_correct"]


def test_projection_avoids_sibling_taint():
    result=tis.run_laundering_scenario(scenario(tis.LaunderingFamily.PROJECTION))
    assert result["field_true_origins"]==result["field_reported_origins"]==1
    assert result["false_taint_expansion"]==0


def test_multi_source_and_corroboration_retain_both_origins():
    for family in (tis.LaunderingFamily.MIXING,tis.LaunderingFamily.CORROBORATION,tis.LaunderingFamily.TRUSTED_CORROBORATION):
        result=tis.run_laundering_scenario(scenario(family))
        assert result["field_true_origins"]==result["field_reported_origins"]==2
        assert result["blocked_escalation"]


def test_label_stripping_becomes_unknown_gap_not_trusted():
    result=tis.label_stripping_trial()
    assert not result["verified"] and result["provenance_gap"]
    assert result["trust"]=="UNKNOWN" and not result["authority_allowed"]


def test_model_metadata_cannot_forge_provenance_or_authority():
    result=tis.metadata_forgery_trial()
    assert result["claimed_metadata"]["trust"]=="TRUSTED"
    assert result["authoritative_trust"]=="UNTRUSTED"
    assert result["grant_count"]==0 and not result["authority_allowed"]


def test_authority_registry_rejects_untrusted_source_and_untrusted_issuer():
    sessions=tis.SessionManager();sessions.create_session("S",user_id="U");manager=tis.TransactionManager(sessions);tx=manager.begin("S");source=manager.issue_provenance(tx,tis.RuntimeSourceType.RETRIEVED_CONTENT,trust_label=tis.TrustLabel.UNTRUSTED);manager.validate(tx);manager.commit(tx);registry=tis.AuthorityRegistry(manager.provenance_registry)
    with pytest.raises(PermissionError):registry.issue(principal_user="U",principal_session="S",permissions=frozenset({"share"}),scope="x",issuer="runtime",reason="bad source",source_provenance_ids=(source.source_id,),transaction_id=tx)
    with pytest.raises(PermissionError):registry.issue(principal_user="U",principal_session="S",permissions=frozenset({"share"}),scope="x",issuer="model",reason="bad issuer",source_provenance_ids=(source.source_id,),transaction_id=tx)


def test_authority_monotonicity_uses_intersection_and_never_invents_permission():
    registry=tis.AuthorityRegistry(tis.ProvenanceRegistry());a=tis.AuthorityContext("U","S",frozenset({"read","share"}),"x",(),(),());b=tis.AuthorityContext("U","S",frozenset({"read"}),"x",(),(),());derived=registry.derive((a,b),principal_user="U",principal_session="S",scope="x")
    assert derived.permissions==frozenset({"read"})


def test_cross_session_grant_reuse_is_denied():assert not tis.cross_session_authority_trial()["allowed"]


def test_declassification_does_not_become_action_authority():
    result=tis.declassification_authority_trial()
    assert result["declassified"] and not result["authority_allowed"] and result["authority_grants"]==0


def test_quarantine_and_invalidated_state_cannot_be_laundered():
    result=tis.restricted_state_laundering_trials()
    assert result["quarantine_copy_gap"] and not result["quarantine_copy_verified"]
    assert not result["quarantine_authority_allowed"] and result["invalidated_reads_blocked"]==3
    assert not result["recovery_copy_allowed"]


def test_depth_eight_and_branching_keep_exact_ancestry():
    depths=tis.stage14b_depth_experiment(repetitions=3)
    assert all(x["correct_attribution"]==x["trials"] for x in depths)
    assert depths[-1]["depth"]==8 and depths[-1]["nodes"]==9
    branch=tis.branching_experiment();assert branch["correct_ancestry"] and branch["false_ancestry"]==0


def test_hard_benign_explicit_grant_is_allowed():
    result=tis.hard_benign_flagship()
    assert result["allowed"] and result["authority_source_ids"]==result["root_sources"]


def test_stage14a_six_gaps_are_analyzed_without_special_rules():
    rows=tis.gap_analysis();assert len(rows)==6
    assert all(x["decision"]=="left as gap" for x in rows)
    assert len({x["classification"] for x in rows})==3


def test_external_asb_persistence_laundering_retains_origins():
    result=tis.external_asb_laundering()
    assert result["correct_root_attribution"]==result["denominator"]==10
    assert result["authority_escalations"]==0


def test_flagships_distinguish_untrusted_claim_from_valid_grant():
    result=tis.flagship_laundering()
    assert result["root_remains_untrusted"] and not result["authority_grant_present"] and not result["effect_allowed"]
    assert result["hard_benign"]["allowed"]


def test_stage14b_corpus_freeze_and_ground_truth_shape():
    document=tis.stage14b_corpus_document();assert len(document["scenarios"])==60
    assert len(tis.stage14b_corpus_hash(document))==64 and document["frozen_before_evaluation"]


def test_authority_grant_does_not_change_frozen_policy_or_validator_fingerprints():
    assert tis.policy_fingerprint(tis.PolicyV1())=="b9c476b30befcd7ae7a34c0effaee6f991cc84d76d64154d56ee95aba460ffb7"
    assert tis.policy_fingerprint(tis.PolicyV2())=="ca3702e69066389a46b785e067ad068d34a6401828d0dfc933523216a386962e"
    assert tis.validator_fingerprints()["PROVENANCE_AWARE"]=="2098e3b676d8032733e7def21ab4c1ae268bd8999257b24c16f3f1c9f7d3f318"
