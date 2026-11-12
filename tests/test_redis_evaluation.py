from transactional_inference_state.redis_evaluation import evaluate_scenarios
from test_redis_participant import InMemoryRedisTransport

def test_redis_read_modify_write_evaluation_scenarios():
    result=evaluate_scenarios(InMemoryRedisTransport())
    assert result["accepted_read_modify_write"]["external_before_commit"]=="10"
    assert result["accepted_read_modify_write"]["external_after_commit"]=="11"
    assert result["accepted_read_modify_write"]["runtime_provenance"]
    assert result["rejected_read_modify_write"]=={"external_after_rollback":"10","transaction_status":"rolled_back","buffer_empty":True}
    assert result["read_your_writes"]["second"]=="B" and result["read_your_writes"]["external_before_commit"]=="A"
    assert result["cross_transaction_isolation"]["t2_observed"]=="A"
    assert result["external_conflict"]=={"conflict_detected":True,"external_after_attempt":"C","transaction_status":"rolled_back"}
    failure=result["redis_failure_during_commit"]
    assert failure["failure_observed"] and not failure["reported_success"]
    assert failure["transaction_status"]=="partially_committed" and failure["external_after_attempt"]=="A"
