"""Scoped external participant design/evaluation model; no runtime integration."""
from __future__ import annotations
import hashlib,json,time
from dataclasses import asdict,dataclass
from enum import Enum

class ProcessScope(str,Enum):
 SINGLE_PROCESS="SINGLE_PROCESS";PROCESS_TREE="PROCESS_TREE";MULTI_SERVICE_GROUP="MULTI_SERVICE_GROUP"
class EligibilityStatus(str,Enum):
 ELIGIBLE_SINGLE_PROCESS="ELIGIBLE_SINGLE_PROCESS";INELIGIBLE_NO_HEALTH_CHECK="INELIGIBLE_NO_HEALTH_CHECK";INELIGIBLE_NO_STATE_ORACLE="INELIGIBLE_NO_STATE_ORACLE";INELIGIBLE_PERSISTENT_SOCKET_REQUIRED="INELIGIBLE_PERSISTENT_SOCKET_REQUIRED";INELIGIBLE_FILESYSTEM_DEPENDENT="INELIGIBLE_FILESYSTEM_DEPENDENT";INELIGIBLE_UNMANAGED_EFFECTS="INELIGIBLE_UNMANAGED_EFFECTS";PROCESS_TREE_NOT_ESTABLISHED="PROCESS_TREE_NOT_ESTABLISHED";MULTI_SERVICE_ATOMICITY_NOT_ESTABLISHED="MULTI_SERVICE_ATOMICITY_NOT_ESTABLISHED"
@dataclass(frozen=True)
class CheckpointParticipantCapabilities:
 process_scope:ProcessScope;requires_reconnect:bool;filesystem_rollback:bool;external_effect_rollback:bool;child_process_support:bool;coordinated_snapshot_support:bool;requires_privileged_host:bool;health_check_available:bool;digest_verification_available:bool;structural_oracle_available:bool;mutation_quiesce_available:bool;restore_failure_observable:bool
@dataclass(frozen=True)
class ParticipantConfiguration:
 participant_id:str;capabilities:CheckpointParticipantCapabilities;filesystem_dependent:bool=False;unmanaged_effects:bool=False;persistent_socket_required:bool=False
@dataclass(frozen=True)
class ParticipantEligibility:
 participant_id:str;status:EligibilityStatus;eligible:bool;reasons:tuple[str,...]
def evaluate_participant(config:ParticipantConfiguration)->ParticipantEligibility:
 c=config.capabilities
 if config.filesystem_dependent:return ParticipantEligibility(config.participant_id,EligibilityStatus.INELIGIBLE_FILESYSTEM_DEPENDENT,False,("mutable filesystem state is outside CRIU process rollback",))
 if config.unmanaged_effects:return ParticipantEligibility(config.participant_id,EligibilityStatus.INELIGIBLE_UNMANAGED_EFFECTS,False,("unmanaged effects survive participant restore",))
 if config.persistent_socket_required:return ParticipantEligibility(config.participant_id,EligibilityStatus.INELIGIBLE_PERSISTENT_SOCKET_REQUIRED,False,("measured participant requires fresh reconnect",))
 if not c.health_check_available:return ParticipantEligibility(config.participant_id,EligibilityStatus.INELIGIBLE_NO_HEALTH_CHECK,False,("health check required",))
 if not(c.digest_verification_available and c.structural_oracle_available):return ParticipantEligibility(config.participant_id,EligibilityStatus.INELIGIBLE_NO_STATE_ORACLE,False,("digest and structural oracles required",))
 if c.process_scope is ProcessScope.PROCESS_TREE and not c.child_process_support:return ParticipantEligibility(config.participant_id,EligibilityStatus.PROCESS_TREE_NOT_ESTABLISHED,False,("managed-child restore failed",))
 if c.process_scope is ProcessScope.MULTI_SERVICE_GROUP and not c.coordinated_snapshot_support:return ParticipantEligibility(config.participant_id,EligibilityStatus.MULTI_SERVICE_ATOMICITY_NOT_ESTABLISHED,False,("sequential checkpoint set is not atomic",))
 mandatory=c.mutation_quiesce_available and c.restore_failure_observable
 return ParticipantEligibility(config.participant_id,EligibilityStatus.ELIGIBLE_SINGLE_PROCESS,mandatory,() if mandatory else ("quiesce and observable failure required",))
@dataclass(frozen=True)
class CheckpointHandle:
 backend:str;participant_id:str;checkpoint_path:str;state_digest:str;sequence:int;process_identity:str;endpoint:str;scope:ProcessScope
 def metadata_hash(self)->str:return hashlib.sha256(json.dumps(asdict(self),sort_keys=True,separators=(",",":"),default=lambda x:x.value).encode()).hexdigest()
@dataclass(frozen=True)
class ParticipantCheckpointSet:
 participant_ids:tuple[str,...];checkpoint_handles:tuple[CheckpointHandle,...];checkpoint_timestamps_ns:tuple[int,...];digests:tuple[str,...];barrier_id:str;checkpoint_order:tuple[str,...];skew_ns:int;mutation_during_checkpoint:bool=False
 @property
 def consistency(self)->str:return "CONSISTENT_UNDER_BARRIER_ASSUMPTION" if not self.mutation_during_checkpoint and self.barrier_id and len(self.participant_ids)==len(self.checkpoint_handles) else "INCONSISTENT_CHECKPOINT_SET"
def measured_single_process_capabilities()->CheckpointParticipantCapabilities:return CheckpointParticipantCapabilities(ProcessScope.SINGLE_PROCESS,True,False,False,False,False,True,True,True,True,True,True)
def participant_matrix()->list[dict[str,object]]:
 base=measured_single_process_capabilities();rows=[ParticipantConfiguration("simple_tool",base),ParticipantConfiguration("simple_rag",base),ParticipantConfiguration("filesystem_tool",base,filesystem_dependent=True),ParticipantConfiguration("observer_tool",base,unmanaged_effects=True),ParticipantConfiguration("persistent_socket_tool",base,persistent_socket_required=True),ParticipantConfiguration("parent_child_tool",CheckpointParticipantCapabilities(ProcessScope.PROCESS_TREE,True,False,False,False,False,True,True,True,True,True,True)),ParticipantConfiguration("multi_service_group",CheckpointParticipantCapabilities(ProcessScope.MULTI_SERVICE_GROUP,True,False,False,False,False,True,True,True,True,True,True))]
 return [{**asdict(x),"capabilities":asdict(x.capabilities),"eligibility":asdict(evaluate_participant(x))} for x in rows]
def scoped_recommendation(tool_success:int,rag_success:int)->dict[str,object]:
 justified=tool_success==20 and rag_success==20
 return {"integration_justified":justified,"supported_scope":["SINGLE_PROCESS"],"unsupported_scope":["FILESYSTEM_DEPENDENT","UNMANAGED_EFFECTS","PERSISTENT_SOCKET_REQUIRED","PROCESS_TREE","ATOMIC_MULTI_SERVICE_GROUP"],"process_tree_status":"NO","second_environment_status":"UNAVAILABLE","reconnect_required":True,"atomic_multiservice":False,"reasons":["fresh single-process health-oracle cycles passed" if justified else "fresh validation incomplete","eligibility is fail-closed","filesystem and observer state remain external","persistent clients do not survive","privileged LinuxKit is the only reproduced environment"]}
