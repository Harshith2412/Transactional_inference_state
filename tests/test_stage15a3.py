import transactional_inference_state.stage15a3 as s

def config(**changes):
 values={"participant_id":"p","capabilities":s.measured_single_process_capabilities()};values.update(changes);return s.ParticipantConfiguration(**values)
def test_capability_model_and_single_process_eligibility():
 result=s.evaluate_participant(config());assert result.eligible and result.status is s.EligibilityStatus.ELIGIBLE_SINGLE_PROCESS
def test_filesystem_and_external_effect_rejection():
 assert s.evaluate_participant(config(filesystem_dependent=True)).status is s.EligibilityStatus.INELIGIBLE_FILESYSTEM_DEPENDENT
 assert s.evaluate_participant(config(unmanaged_effects=True)).status is s.EligibilityStatus.INELIGIBLE_UNMANAGED_EFFECTS
def test_persistent_socket_and_process_tree_classification():
 assert s.evaluate_participant(config(persistent_socket_required=True)).status is s.EligibilityStatus.INELIGIBLE_PERSISTENT_SOCKET_REQUIRED
 row=next(x for x in s.participant_matrix() if x["participant_id"]=="parent_child_tool");assert row["eligibility"]["status"] is s.EligibilityStatus.PROCESS_TREE_NOT_ESTABLISHED
def test_checkpoint_set_consistency_oracle():
 h=s.CheckpointHandle("CRIU","a","/x","d",1,"1","localhost",s.ProcessScope.SINGLE_PROCESS);good=s.ParticipantCheckpointSet(("a",),(h,),(1,),("d",),"barrier",("a",),0);bad=s.ParticipantCheckpointSet(("a",),(h,),(1,),("d",),"barrier",("a",),0,True);assert good.consistency=="CONSISTENT_UNDER_BARRIER_ASSUMPTION" and bad.consistency=="INCONSISTENT_CHECKPOINT_SET";assert len(h.metadata_hash())==64
def test_recommendation_allows_only_scoped_single_process():
 result=s.scoped_recommendation(20,20);assert result["integration_justified"] and result["supported_scope"]==["SINGLE_PROCESS"] and not result["atomic_multiservice"]
