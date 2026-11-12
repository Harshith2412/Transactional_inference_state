"""Artifact writer for Stage 14A external-validation results."""
from __future__ import annotations
from dataclasses import asdict
import csv,json
from pathlib import Path
from typing import Any
from .stage14a import excluded_tasks,external_tasks,evaluate_stage14a,manifest_document,manifest_hash

def _json(path:Path,value:Any):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def _csv(path:Path,rows:list[dict[str,Any]]):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("w",newline="") as stream:writer=csv.DictWriter(stream,fieldnames=list(rows[0]) if rows else []);writer.writeheader();writer.writerows(rows)
def _svg(path:Path,title:str,labels:list[str],values:list[float]):
    path.parent.mkdir(parents=True,exist_ok=True);maximum=max(values or [1]) or 1;bars=[]
    for i,(label,value) in enumerate(zip(labels,values)):
        width=600*value/maximum;y=55+i*32;bars.append(f'<text x="8" y="{y+15}" font-size="11">{label}</text><rect x="190" y="{y}" width="{width:.2f}" height="20" fill="#7c3aed"/><text x="{200+width:.2f}" y="{y+15}" font-size="11">{value:.3f}</text>')
    path.write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="900" height="{80+32*len(bars)}"><text x="8" y="25" font-size="18">{title}</text>{"".join(bars)}</svg>\n')

def generate_stage14a_artifacts(destination:str|Path)->dict[str,Any]:
    root=Path(destination);root.mkdir(parents=True,exist_ok=True);manifest=manifest_document()
    # The corpus and digest are durably written before any validator execution.
    manifest_path=root/"corpus/external_manifest.json";manifest_path.parent.mkdir(parents=True,exist_ok=True);manifest_path.write_text(json.dumps(manifest,sort_keys=True,separators=(",",":")));(root/"corpus/external_manifest.sha256").write_text(manifest_hash(manifest)+"\n");_json(root/"corpus/excluded_tasks.json",excluded_tasks())
    result=evaluate_stage14a()
    if result["manifest_hash"]!=(root/"corpus/external_manifest.sha256").read_text().strip():raise RuntimeError("external manifest changed after freeze")
    primary=result["primary_memory"];secondary=result["secondary_agent"]
    _json(root/"primary_memory/results.json",primary);_json(root/"secondary_agent/results.json",secondary);_json(root/"provenance/results.json",result["provenance"]);_json(root/"recovery/results.json",result["recovery"]);_json(root/"comparisons/results.json",result["comparison"]);_json(root/"failures/taxonomy.json",result["failures"]);_json(root/"adapters/adapter_manifest.json",{"version":manifest["adapter_version"],"tasks":len(manifest["tasks"])})
    inventory=manifest["tasks"];adapt=[{"task_id":x["task_id"],"source":x["source_reference"],"adaptation":x["adaptation_notes"],"instrumentation":x["instrumentation"]} for x in inventory]
    validator_rows=[]
    for name,metric in result["validators"]["metrics"].items():validator_rows.append({"validator":name,**metric})
    failure_counts={}
    for row in result["failures"]:failure_counts[row["category"]]=failure_counts.get(row["category"],0)+1
    tables={"01_external_task_inventory.json":inventory,"02_adaptation_summary.json":adapt,"03_primary_memory_security_results.json":primary["policy_summary"],"04_secondary_agent_security_results.json":secondary,"05_validator_comparison.json":validator_rows,"06_persistent_compromise_leakage.json":{"primary":primary["policy_summary"],"external_leakage":sum(x["external_leakage"] for x in primary["trials"])},"07_recovery_results.json":result["recovery"],"08_provenance_coverage.json":result["provenance"],"09_internal_vs_external_comparison.json":result["comparison"],"10_failure_taxonomy.json":failure_counts}
    for name,value in tables.items():_json(root/"tables"/name,value)
    metrics=result["validators"]["metrics"];external=result["comparison"]["external"];figures=[("01_adapter_architecture.svg","External definitions → adapter → frozen runtime",["external tasks","adapted tasks"],[len(inventory),len(inventory)]),("02_memory_lifecycle_outcomes.svg","Primary memory lifecycle",["persistent compromise","forced containment","recovery success"],[primary["policy_summary"]["persistent_compromise"],primary["policy_summary"]["containment_after_forced_rejection"],primary["policy_summary"]["recovery_success"]]),("03_persistent_compromise_by_workload.svg","Persistent compromise rate",["internal","external"],[.55,external["persistent_compromise"]]),("04_validator_recall_across_workloads.svg","External validator recall",list(metrics),[x["recall"] for x in metrics.values()]),("05_benign_completion_across_workloads.svg","Benign completion",["internal","external"],[1.0,external["benign_completion"]]),("06_recovery_success.svg","Recovery success",["origin","preservation","reuse blocked"],[result["recovery"]["origin_correct"],result["recovery"]["unrelated_preserved"],result["recovery"]["post_recovery_reuse_blocked"]]),("07_provenance_coverage.svg","External provenance coverage",["covered","gap rate"],[result["provenance"]["provenance_coverage"],result["provenance"]["gap_rate"]]),("08_internal_vs_external.svg","Cross-workload comparison",["internal policy recall","external policy recall","internal containment","external containment"],[.45,external["policy_recall"],1.0,external["containment_after_rejection"]])]
    for name,title,labels,values in figures:_svg(root/"figures"/name,title,labels,values)
    _json(root/"report/stage14a_results.json",result);return result
