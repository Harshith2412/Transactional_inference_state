import pytest
import transactional_inference_state as tis
from transactional_inference_state.stage15a3 import EligibilityStatus,ParticipantEligibility
from transactional_inference_state.stage15b import ExternalParticipantCoordinator,ExternalRollbackError,InMemoryCheckpointParticipant,ParticipantEnrollmentError,classify_external_recovery

def eligible(pid="p"):return ParticipantEligibility(pid,EligibilityStatus.ELIGIBLE_SINGLE_PROCESS,True,())
def runtime(accepted=True):
 sessions=tis.SessionManager();sessions.create_session("S",user_id="U");manager=tis.TransactionManager(sessions,validator=tis.PolicyValidator(accepted));return sessions,manager,ExternalParticipantCoordinator(manager)
def participant(**kw):return InMemoryCheckpointParticipant("p",{"role":"user","counter":0,"history":[]},eligible(),**kw)

def test_portable_participant_interface_and_checkpoint_metadata():
 p=participant();h=p.checkpoint();assert h.participant_id=="p" and h.backend=="IN_MEMORY_TEST_DOUBLE" and len(h.metadata_hash())==64
def test_begin_checkpoint_failure_never_creates_active_transaction():
 _,m,c=runtime();p=participant(fail_checkpoint=True)
 with pytest.raises(ExternalRollbackError):c.begin("S",p)
 assert not m.event_log.events
def test_unsupported_participants_rejected_before_begin():
 for status in list(EligibilityStatus)[1:]:
  _,m,c=runtime();p=InMemoryCheckpointParticipant("bad",{},ParticipantEligibility("bad",status,False,("unsupported",)))
  with pytest.raises(ParticipantEnrollmentError):c.begin("S",p)
  assert not m.event_log.events
def test_max_one_external_participant():
 _,_,c=runtime()
 with pytest.raises(ParticipantEnrollmentError):c.begin("S",[participant(),participant()])
def test_commit_preserves_external_mutation_and_releases_checkpoint():
 sessions,m,c=runtime(True);p=participant();tx=c.begin("S",p);p.state["role"]="admin";m.write_private(tx,"S","session_memory","x","committed");m.validate(tx);c.commit(tx);assert p.state["role"]=="admin" and sessions.get_session("S").session_memory["x"]=="committed" and p.released and m.status(tx) is tis.TransactionStatus.COMMITTED
def test_rollback_restores_local_and_external_state_with_events():
 sessions,m,c=runtime(False);p=participant();tx=c.begin("S",p);p.state.update(role="admin",counter=1,history=["unsafe-operation"]);m.write_private(tx,"S","session_memory","unsafe","x");m.validate(tx);c.rollback(tx);assert sessions.get_session("S").session_memory=={} and p.state=={"role":"user","counter":0,"history":[]} and m.status(tx) is tis.TransactionStatus.ROLLED_BACK;events={x.event_type for x in m.event_log.events};assert {"EXTERNAL_PARTICIPANT_ENROLLED","EXTERNAL_CHECKPOINT_CREATED","EXTERNAL_RESTORE_SUCCESS","EXTERNAL_RECONNECTED","EXTERNAL_STATE_VERIFIED"}<=events
def test_external_failure_is_not_reported_rolled_back_and_can_retry():
 _,m,c=runtime(False);p=participant(fail_restore_attempts=1);tx=c.begin("S",p);p.state["role"]="admin";m.validate(tx)
 with pytest.raises(ExternalRollbackError):c.rollback(tx)
 assert m.status(tx) is tis.TransactionStatus.EXTERNAL_ROLLBACK_FAILED;enrollment=c.enrollment(tx);assert enrollment.local_rollback is True and enrollment.external_rollback is False and enrollment.handle.checkpoint_path in p.snapshots
 c.retry_external_restore(tx);assert m.status(tx) is tis.TransactionStatus.ROLLED_BACK and p.state["role"]=="user" and c.recovery_history
def test_cleanup_failure_does_not_undo_commit():
 _,m,c=runtime(True);p=participant(fail_release=True);tx=c.begin("S",p);m.validate(tx);c.commit(tx);assert m.status(tx) is tis.TransactionStatus.COMMITTED and c.enrollment(tx).cleanup_failed
def test_checkpoint_journal_metadata_and_recovery_classification(tmp_path):
 sessions=tis.SessionManager();sessions.create_session("S",user_id="U");m=tis.TransactionManager(sessions,validator=tis.PolicyValidator(False));journal=tis.TransactionJournal(tmp_path/"j.jsonl",fsync=False);c=ExternalParticipantCoordinator(m,journal=journal);p=participant(fail_restore_attempts=1);tx=c.begin("S",p);m.validate(tx)
 with pytest.raises(ExternalRollbackError):c.rollback(tx)
 records=journal.read_records();assert tis.JournalRecordType.EXTERNAL_CHECKPOINT in [x.record_type for x in records];assert classify_external_recovery(records) is tis.RecoveryClassification.EXTERNAL_ROLLBACK_INCOMPLETE
def test_crash_after_restore_before_complete_requires_reverification(tmp_path):
 sessions=tis.SessionManager();sessions.create_session("S");m=tis.TransactionManager(sessions,validator=tis.PolicyValidator(False));journal=tis.TransactionJournal(tmp_path/"j.jsonl",fsync=False);c=ExternalParticipantCoordinator(m,journal=journal);p=participant();tx=c.begin("S",p);m.validate(tx);c.rollback(tx);records=journal.read_records();assert classify_external_recovery(records) is tis.RecoveryClassification.COMPLETE;without_complete=[x for x in records if x.record_type is not tis.JournalRecordType.TX_COMPLETE];assert classify_external_recovery(without_complete) is tis.RecoveryClassification.EXTERNAL_RESTORE_VERIFICATION_REQUIRED
def test_provenance_and_authority_are_not_sanitized_by_checkpointability():
 sessions,m,c=runtime(False);p=participant();tx=c.begin("S",p);source=m.issue_provenance(tx,tis.RuntimeSourceType.RETRIEVED_CONTENT,trust_label=tis.TrustLabel.UNTRUSTED);m.write_private(tx,"S","session_memory","unsafe","x",provenance_ids=(source.source_id,));m.validate(tx);c.rollback(tx);assert sessions.get_session("S").provenance_metadata=={};registry=tis.AuthorityRegistry(m.provenance_registry);assert not registry.authorize(registry.context(principal_user="U",principal_session="S",scope="x"),permission="share",scope="x",principal_user="U",principal_session="S").allowed
