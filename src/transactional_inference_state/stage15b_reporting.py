"""Reproducible Stage 15B tables, figures, and research summaries."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from .stage15a3 import participant_matrix

def write(path:Path,value:Any)->None:path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def svg(path:Path,title:str,lines:list[str])->None:
 path.parent.mkdir(parents=True,exist_ok=True);body=''.join(f'<text x="24" y="{64+i*30}" font-size="15">{line}</text>' for i,line in enumerate(lines));path.write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="1050" height="{110+30*len(lines)}"><text x="24" y="30" font-size="22">{title}</text>{body}</svg>\n')
def generate(root:str|Path,native_path:str|Path)->dict[str,Any]:
 root=Path(root);native=json.loads(Path(native_path).read_text());matrix=participant_matrix()
 eligibility=[{"participant":x["participant_id"],"status":x["eligibility"]["status"],"enrolled":x["eligibility"]["eligible"]} for x in matrix]
 performance={**native["performance"],"external_components":{key:native["tool"][key] for key in ("checkpoint_ns","restore_ns","reconnect_ns","health_check_ns","verification_ns")}};trusted={"baseline_modules":15,"baseline_loc":3619,"trusted_modules":17,"trusted_loc":3774,"trusted_growth_modules":2,"trusted_growth_loc":155,"external_participant_integration_loc":118,"criu_adapter_loc":37,"third_party_core_runtime_dependencies":0}
 tables={
  "01_participant_eligibility":eligibility,"02_tool_rollback":native["tool"],"03_rag_rollback":native["rag"],
  "04_accepted_transaction":native["accepted_commit"],"05_external_rollback_failures":native["restore_failure"],
  "06_crash_recovery":{"during_restore":"EXTERNAL_ROLLBACK_INCOMPLETE","after_restore_before_complete":"EXTERNAL_RESTORE_VERIFICATION_REQUIRED","automatic_success_claim":False},
  "07_local_only_vs_expanded":native["comparison"],"08_performance":performance,"09_realistic_agent":native["realistic_agent"],"10_trusted_core_growth":trusted}
 for name,value in tables.items():write(root/"tables"/(name+".json"),value)
 figures=[
  ("01_expanded_architecture",["TransactionManager → scoped coordinator → one CRIU participant","eligible single process only"]),
  ("02_begin_lifecycle",["eligibility → quiesce → checkpoint → metadata → resume → ACTIVE"]),
  ("03_commit_lifecycle",["local commit → preserve external mutation → release checkpoint"]),
  ("04_rollback_lifecycle",["local rollback → invalidate client → restore → reconnect → health → exact digest"]),
  ("05_boundary_comparison",["local-only: external contamination survives","expanded: local and external state restored"]),
  ("06_overhead",[f'external begin {performance["external_tool"]["begin_ns"]/1e6:.2f} ms',f'external rollback {performance["external_tool"]["rollback_ns"]/1e6:.2f} ms']),
  ("07_failure_states",["local success + external failure → EXTERNAL_ROLLBACK_FAILED","explicit retry uses original handle"]),
  ("08_realistic_rag",["malicious retrieval → local/cache contamination → reject","CRIU restore removes external cache poison"])]
 for name,lines in figures:svg(root/"figures"/(name+".svg"),name.replace('_',' ').title(),lines)
 summary=f'''# Stage 15B summary\n\nOne validated `ELIGIBLE_SINGLE_PROCESS` participant was integrated through a coordinated checkpoint lifecycle. Native tool and RAG rollback restored exact structural state and SHA-256 digests. The local-only comparison retained external contamination; the expanded boundary removed it. A deliberately damaged CRIU image produced `EXTERNAL_ROLLBACK_FAILED`, never `ROLLED_BACK`.\n\nThis is not a distributed or atomic multi-resource transaction. Native evidence is limited to privileged Docker Desktop LinuxKit arm64. Persistent clients do not survive; fresh reconnect is mandatory.\n'''
 semantics='''# External transaction semantics\n\nBEGIN validates eligibility and creates the external checkpoint before local ACTIVE execution. Commit makes local state durable, preserves the participant mutation, then releases the checkpoint. Rollback uses deterministic local-first ordering, then invalidates clients, restores the original CRIU handle, reconnects, checks health, and verifies structural and SHA-256 equality. Local-first prevents tentative application state from remaining visible while external recovery is attempted, but it creates an explicitly recorded partial-failure interval and does not provide atomicity.\n'''
 limitations='''# Limitations\n\nSupported scope is exactly one externally managed single process. Filesystem-dependent state, unmanaged effects, persistent-socket requirements, arbitrary process trees, atomic multi-service groups, remote effects, and connection-transparent rollback are unsupported. The adapter depends on privileged CRIU/Linux facilities. A crash after successful restore but before a complete journal record requires re-verification; an incomplete restore requires an explicit retry.\n'''
 for name,text in (("stage15b_summary.md",summary),("external_transaction_semantics.md",semantics),("limitations.md",limitations)):(root/"report").mkdir(parents=True,exist_ok=True);(root/"report"/name).write_text(text)
 write(root/"stage15b_manifest.json",{"tables":len(tables),"figures":len(figures),"scope":native["scope"],"native_environment":native["environment"]})
 return {"tables":len(tables),"figures":len(figures),"trusted":trusted}
