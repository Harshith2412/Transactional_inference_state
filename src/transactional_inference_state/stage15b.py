"""Scoped single-process external participant integration."""
from __future__ import annotations
import time
from copy import deepcopy
from dataclasses import asdict,dataclass
from typing import Any,Protocol
from .durability import JournalRecordType,RecoveryClassification,TransactionJournal
from .runtime import TransactionError,TransactionManager,TransactionStatus
from .stage15a import canonical_digest
from .stage15a3 import CheckpointHandle,EligibilityStatus,ParticipantEligibility,ProcessScope

class ExternalRollbackError(TransactionError):pass
class ParticipantEnrollmentError(TransactionError):pass
@dataclass(frozen=True)
class RestoreResult:
 command_success:bool;reachable:bool;health_pass:bool;structural_equal:bool;digest_equal:bool;reconnect_success:bool;error:str|None=None
 @property
 def success(self)->bool:return all((self.command_success,self.reachable,self.health_pass,self.structural_equal,self.digest_equal,self.reconnect_success))
class ExternalTransactionParticipant(Protocol):
 participant_id:str
 def eligibility(self)->ParticipantEligibility:...
 def quiesce(self)->None:...
 def checkpoint(self)->CheckpointHandle:...
 def resume(self)->None:...
 def invalidate_client(self)->None:...
 def restore(self,handle:CheckpointHandle)->RestoreResult:...
 def reconnect(self)->None:...
 def health_check(self)->bool:...
 def verify_state(self,handle:CheckpointHandle)->bool:...
 def release(self,handle:CheckpointHandle)->None:...
@dataclass
class ExternalEnrollment:
 participant:ExternalTransactionParticipant;handle:CheckpointHandle;session_id:str;local_rollback:bool|None=None;external_rollback:bool|None=None;cleanup_failed:bool=False;restore_attempts:int=0;metrics_ns:dict[str,int]|None=None

class ExternalParticipantCoordinator:
 """Coordinates one eligible process; it is not an atomic distributed transaction."""
 def __init__(self,manager:TransactionManager,*,journal:TransactionJournal|None=None):self.manager=manager;self.journal=journal;self._enrollments={};self.recovery_history=[]
 def begin(self,session_id:str,participant:ExternalTransactionParticipant|None=None)->str:
  if participant is None:return self.manager.begin(session_id)
  if isinstance(participant,(list,tuple)):raise ParticipantEnrollmentError("max_external_participants=1")
  eligibility=participant.eligibility()
  if not eligibility.eligible or eligibility.status is not EligibilityStatus.ELIGIBLE_SINGLE_PROCESS:raise ParticipantEnrollmentError(eligibility.status.value)
  participant.quiesce()
  try:handle=participant.checkpoint()
  except Exception:
   participant.resume();raise
  participant.resume();tx=self.manager.begin(session_id);self._enrollments[tx]=ExternalEnrollment(participant,handle,session_id)
  self._event("EXTERNAL_PARTICIPANT_ENROLLED",tx,participant_id=participant.participant_id);self._event("EXTERNAL_CHECKPOINT_BEGIN",tx,participant_id=participant.participant_id);self._event("EXTERNAL_CHECKPOINT_CREATED",tx,participant_id=participant.participant_id,handle=self._metadata(handle));self._journal(JournalRecordType.EXTERNAL_CHECKPOINT,tx,session_id,{"participant_id":participant.participant_id,"handle":self._metadata(handle)});return tx
 def commit(self,transaction_id:str)->None:
  self.manager.commit(transaction_id);enrollment=self._enrollments.get(transaction_id)
  if enrollment is None:return
  try:enrollment.participant.release(enrollment.handle);self._event("EXTERNAL_CHECKPOINT_RELEASED",transaction_id,participant_id=enrollment.participant.participant_id);self._journal(JournalRecordType.EXTERNAL_CHECKPOINT_RELEASE,transaction_id,enrollment.session_id,{"participant_id":enrollment.participant.participant_id})
  except Exception as error:enrollment.cleanup_failed=True;self._event("CHECKPOINT_CLEANUP_FAILED",transaction_id,participant_id=enrollment.participant.participant_id,error=str(error))
 def rollback(self,transaction_id:str)->None:
  enrollment=self._enrollments.get(transaction_id)
  self.manager.rollback(transaction_id)
  if enrollment is None:return
  enrollment.local_rollback=True
  try:self._restore(transaction_id,enrollment)
  except Exception as error:
   enrollment.external_rollback=False;self.manager.mark_external_rollback_failed(transaction_id);self._event("EXTERNAL_RESTORE_FAILED",transaction_id,participant_id=enrollment.participant.participant_id,error=str(error),local_rollback="SUCCESS",external_rollback="FAILURE");self._journal(JournalRecordType.EXTERNAL_RESTORE_FAILURE,transaction_id,enrollment.session_id,{"participant_id":enrollment.participant.participant_id,"error":str(error)});raise ExternalRollbackError(str(error)) from error
 def retry_external_restore(self,transaction_id:str)->None:
  if self.manager.status(transaction_id) is not TransactionStatus.EXTERNAL_ROLLBACK_FAILED:raise TransactionError("transaction has no retryable external failure")
  enrollment=self._enrollments[transaction_id];self._restore(transaction_id,enrollment);self.manager.mark_external_rollback_recovered(transaction_id);self.recovery_history.append({"transaction_id":transaction_id,"attempt":enrollment.restore_attempts,"outcome":"SUCCESS"});self._event("EXTERNAL_RESTORE_RECOVERED",transaction_id,participant_id=enrollment.participant.participant_id,attempt=enrollment.restore_attempts)
 def enrollment(self,transaction_id:str)->ExternalEnrollment:return self._enrollments[transaction_id]
 def _restore(self,tx:str,e:ExternalEnrollment)->None:
  e.restore_attempts+=1;self._event("EXTERNAL_RESTORE_BEGIN",tx,participant_id=e.participant.participant_id,attempt=e.restore_attempts);self._journal(JournalRecordType.EXTERNAL_RESTORE_ATTEMPT,tx,e.session_id,{"participant_id":e.participant.participant_id,"attempt":e.restore_attempts});e.participant.invalidate_client();e.participant.quiesce();result=e.participant.restore(e.handle)
  if not result.success:raise ExternalRollbackError(result.error or "external restore health oracle failed")
  mark=time.perf_counter_ns();e.participant.reconnect();reconnect_ns=time.perf_counter_ns()-mark
  mark=time.perf_counter_ns();healthy=e.participant.health_check();health_ns=time.perf_counter_ns()-mark
  mark=time.perf_counter_ns();verified=e.participant.verify_state(e.handle);verification_ns=time.perf_counter_ns()-mark;e.metrics_ns={"reconnect_ns":reconnect_ns,"health_check_ns":health_ns,"verification_ns":verification_ns}
  if not healthy or not verified:raise ExternalRollbackError("post-reconnect verification failed")
  e.external_rollback=True;self._event("EXTERNAL_RESTORE_SUCCESS",tx,participant_id=e.participant.participant_id);self._event("EXTERNAL_RECONNECTED",tx,participant_id=e.participant.participant_id);self._event("EXTERNAL_STATE_VERIFIED",tx,participant_id=e.participant.participant_id);self._journal(JournalRecordType.EXTERNAL_RESTORE_SUCCESS,tx,e.session_id,{"participant_id":e.participant.participant_id,"digest":e.handle.state_digest});self._journal(JournalRecordType.TX_COMPLETE,tx,e.session_id,{"external_rollback_verified":True})
 def _event(self,name:str,tx:str,**details:Any)->None:self.manager.event_log.record(name,tx,session_id=self._enrollments.get(tx).session_id if tx in self._enrollments else None,**details)
 def _journal(self,kind:JournalRecordType,tx:str,session:str,payload:dict[str,Any])->None:
  if self.journal:self.journal.append(kind,tx,session,payload)
 @staticmethod
 def _metadata(handle:CheckpointHandle)->dict[str,Any]:return {**asdict(handle),"scope":handle.scope.value,"metadata_hash":handle.metadata_hash()}

class InMemoryCheckpointParticipant:
 """Portable deterministic participant double using the production contract."""
 def __init__(self,participant_id:str,state:dict[str,Any],eligibility:ParticipantEligibility,*,fail_checkpoint:bool=False,fail_restore_attempts:int=0,fail_release:bool=False):self.participant_id=participant_id;self.state=deepcopy(state);self._eligibility=eligibility;self.fail_checkpoint=fail_checkpoint;self.fail_restore_attempts=fail_restore_attempts;self.fail_release=fail_release;self.snapshots={};self.sequence=0;self.connected=True;self.released=[]
 def eligibility(self):return self._eligibility
 def quiesce(self):pass
 def resume(self):pass
 def checkpoint(self):
  if self.fail_checkpoint:raise ExternalRollbackError("checkpoint failed")
  self.sequence+=1;path=f"memory://{self.participant_id}/{self.sequence}";self.snapshots[path]=deepcopy(self.state);return CheckpointHandle("IN_MEMORY_TEST_DOUBLE",self.participant_id,path,canonical_digest(self.state),self.sequence,str(id(self)),f"memory:{self.participant_id}",ProcessScope.SINGLE_PROCESS)
 def invalidate_client(self):self.connected=False
 def restore(self,handle):
  if self.fail_restore_attempts>0:self.fail_restore_attempts-=1;return RestoreResult(False,False,False,False,False,False,"injected restore failure")
  self.state=deepcopy(self.snapshots[handle.checkpoint_path]);return RestoreResult(True,True,True,canonical_digest(self.state)==handle.state_digest,canonical_digest(self.state)==handle.state_digest,True)
 def reconnect(self):self.connected=True
 def health_check(self):return self.connected
 def verify_state(self,handle):return canonical_digest(self.state)==handle.state_digest
 def release(self,handle):
  if self.fail_release:raise ExternalRollbackError("cleanup failed")
  self.snapshots.pop(handle.checkpoint_path,None);self.released.append(handle.checkpoint_path)

def classify_external_recovery(records:list[Any])->RecoveryClassification:
 types=[x.record_type for x in records]
 if JournalRecordType.TX_COMPLETE in types:return RecoveryClassification.COMPLETE
 if JournalRecordType.EXTERNAL_RESTORE_SUCCESS in types:return RecoveryClassification.EXTERNAL_RESTORE_VERIFICATION_REQUIRED
 if JournalRecordType.EXTERNAL_RESTORE_ATTEMPT in types and JournalRecordType.EXTERNAL_RESTORE_SUCCESS not in types:return RecoveryClassification.EXTERNAL_ROLLBACK_INCOMPLETE
 if JournalRecordType.EXTERNAL_RESTORE_FAILURE in types:return RecoveryClassification.EXTERNAL_ROLLBACK_INCOMPLETE
 return RecoveryClassification.COMPLETE
