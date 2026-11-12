"""Stage 14B artifact generation."""
from __future__ import annotations
import csv,json
from pathlib import Path
from typing import Any
from .stage14b import corpus_document,corpus_hash,evaluate_stage14b

def _json(path:Path,value:Any):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2,sort_keys=True,default=repr)+"\n")
def _svg(path:Path,title:str,labels:list[str],values:list[float]):
    path.parent.mkdir(parents=True,exist_ok=True);maximum=max(values or [1]) or 1;items=[]
    for i,(label,value) in enumerate(zip(labels,values)):
        width=600*value/maximum;y=55+i*32;items.append(f'<text x="8" y="{y+15}" font-size="11">{label}</text><rect x="190" y="{y}" width="{width:.2f}" height="20" fill="#059669"/><text x="{200+width:.2f}" y="{y+15}" font-size="11">{value:.3f}</text>')
    path.write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="900" height="{80+32*len(items)}"><text x="8" y="25" font-size="18">{title}</text>{"".join(items)}</svg>\n')

def generate_stage14b_artifacts(destination:str|Path)->dict[str,Any]:
    root=Path(destination);root.mkdir(parents=True,exist_ok=True);document=corpus_document();path=root/"corpus/laundering_corpus.json";path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(document,sort_keys=True,separators=(",",":")));(root/"corpus/laundering_corpus.sha256").write_text(corpus_hash(document)+"\n");result=evaluate_stage14b()
    if result["corpus_hash"]!=(root/"corpus/laundering_corpus.sha256").read_text().strip():raise RuntimeError("Stage 14B corpus changed after freeze")
    _json(root/"laundering/results.json",{"summary":result["summary"],"trials":result["trials"]});_json(root/"authority/results.json",{x:result[x] for x in ("metadata_forgery","cross_session","declassification","restricted_state")});_json(root/"external_asb/results.json",result["external_asb"]);_json(root/"gaps/results.json",result["gaps"]);_json(root/"depth/results.json",result["depth"]);_json(root/"recovery/results.json",result["recovery"]);_json(root/"performance/results.json",result["depth"])
    tables={"01_laundering_attack_corpus.json":document["scenarios"],"02_provenance_survival_by_attack.json":result["trials"],"03_authority_escalation_results.json":result["summary"],"04_depth_results.json":result["depth"],"05_stage14a_gap_analysis.json":result["gaps"],"06_validator_comparison.json":result["validators"]["metrics"],"07_hard_benign_controls.json":{"summary":result["summary"],"flagship":result["flagship"]["hard_benign"]},"08_attribution_recovery.json":result["recovery"],"09_performance.json":result["depth"],"10_trusted_core_impact.json":result["trusted_core"]}
    for name,value in tables.items():_json(root/"tables"/name,value)
    summary=result["summary"];depth=result["depth"];validators=result["validators"]["metrics"];figures=[("01_provenance_authority_architecture.svg","Provenance origins ≠ action authority",["provenance","grants"],[1,1]),("02_laundering_chain.svg","Flagship chain nodes/edges",["nodes","edges"],[result["flagship"]["graph"]["nodes"],result["flagship"]["graph"]["edges"]]),("03_provenance_coverage.svg","Coverage",["covered","gaps"],[summary["provenance_coverage"],summary["provenance_gap_rate"]]),("04_authority_escalation_outcomes.svg","Authority escalation",["blocked","successful","valid grants"],[summary["blocked_authority_escalations"],summary["successful_unauthorized_escalations"],summary["valid_grants_accepted"]]),("05_depth_vs_attribution.svg","Attribution by depth",[str(x["depth"]) for x in depth],[x["success_rate"] for x in depth]),("06_false_taint_expansion.svg","Field provenance",["precision","recall","false expansion"],[summary["field_precision"],summary["field_recall"],summary["false_taint_expansion"]]),("07_validator_behavior.svg","Validator recall",list(validators),[x["recall"] for x in validators.values()]),("08_propagation_query_overhead.svg","Depth-8 overhead (ns)",["propagation median","query median"],[depth[-1]["propagation_median_ns"],depth[-1]["query_median_ns"]])]
    for name,title,labels,values in figures:_svg(root/"figures"/name,title,labels,values)
    _json(root/"report/stage14b_results.json",result);return result
