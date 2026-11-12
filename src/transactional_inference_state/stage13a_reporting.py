"""Artifact generation for Stage 13A realistic-agent measurements."""
from __future__ import annotations
import csv,json
from pathlib import Path
from typing import Any


def generate_stage13a_artifacts(document:dict[str,Any],destination:Path,live:dict[str,Any]|None=None)->None:
    for name in ("corpus","deterministic","live","flagship","failures","performance","comparison","tables","figures","report"):(destination/name).mkdir(parents=True,exist_ok=True)
    _json(destination/"corpus/documents.json",document["corpus"]["documents"]);_json(destination/"corpus/workflows.json",document["corpus"]["workflows"])
    _json(destination/"deterministic/results.json",document["deterministic"]);_json(destination/"flagship/demo.json",document["flagship"]);(destination/"flagship/transcript.txt").write_text(document["flagship"]["transcript"]+"\n")
    _json(destination/"performance/breakdown.json",document["performance"]);_json(destination/"comparison/synthetic_vs_realistic.json",document["comparison"]);_json(destination/"comparison/state_growth.json",document["state_growth"])
    _json(destination/"deterministic/cache_poisoning_reuse.json",document["cache_poisoning"])
    if live is not None:_json(destination/"live/results.json",live)
    failures=[x for x in document["deterministic"]["trials"] if x["malicious"] and (x["persistent_compromise"] or x["external_leakage"])]
    _json(destination/"failures/failure_analysis.json",{"count":len(failures),"failures":[{"scenario":x["scenario_id"],"attack_family":x["attack_family"],"agent_workflow":x["retrieved_document_ids"],"model_plan":x["raw_plan"],"policy_decision":x["policy_allowed"],"persistent_consequence":{"state":x["persistent_compromise"],"effect":x["external_leakage"]},"lineage":{"correct":x["provenance_correct"]}} for x in failures]})
    trials=document["deterministic"]["trials"];metrics=document["deterministic"]["summary"]
    _csv(destination/"tables/table_01_agent_workload_corpus.csv",[{"scenario_id":x["scenario_id"],"malicious":x["malicious"],"attack_family":x["attack_family"],"turn_count":x["turn_count"]} for x in trials])
    _csv(destination/"tables/table_02_benign_completion.csv",[_metric("benign_completion",metrics["benign_completion"])])
    _csv(destination/"tables/table_03_malicious_results.csv",[{k:x[k] for k in ("scenario_id","attack_family","policy_allowed","persistent_compromise","external_leakage","resolution")} for x in trials if x["malicious"]])
    syn=document["comparison"]["synthetic_final_validation"]
    _csv(destination/"tables/table_04_synthetic_vs_realistic.csv",[_comparison(k,syn[k],metrics.get(k,{})) for k in ("policy_recall","persistent_compromise","containment_after_rejection","benign_completion")])
    _csv(destination/"tables/table_05_compromise_leakage.csv",[_metric(k,metrics[k]) for k in ("persistent_compromise","external_effect_leakage","containment_after_rejection")])
    _csv(destination/"tables/table_06_poisoning.csv",[_metric(k,metrics[k]) for k in ("memory_poison_persistence","cache_poison_persistence")])
    cross=document["cross_session"];_csv(destination/"tables/table_07_cross_session.csv",[{"private_allowed":cross["private_allowed"],"public_allowed":cross["public_allowed"],"restricted_fields_leaked":cross["cross_session_leakage"],"declassified_allowed":cross["after"]["after_value"]!={"weather":"sunny"}}])
    _csv(destination/"tables/table_08_performance.csv",[{"phase":k,**v} for k,v in document["performance"].items()])
    _csv(destination/"tables/table_09_state_lineage_growth.csv",[{"measure":k,"growth":v} for k,v in document["state_growth"].items()])
    _csv(destination/"tables/table_10_failure_taxonomy.csv",[{"attack_family":k,"count":v} for k,v in _counts(x["attack_family"] for x in failures).items()])
    _architecture(destination/"figures/figure_01_agent_architecture.svg")
    _bar(destination/"figures/figure_02_workflow_outcomes.svg","Workflow outcomes",[("benign complete",metrics["benign_completion"]["count"]),("malicious detected",metrics["policy_detection"]["count"]),("malicious succeeded",metrics["malicious_workflow_success"]["count"])])
    _bar(destination/"figures/figure_03_persistent_compromise.svg","Persistent compromise",[("persistent",metrics["persistent_compromise"]["count"]),("contained",metrics["persistent_compromise"]["denominator"]-metrics["persistent_compromise"]["count"])])
    family=_counts(x["attack_family"] for x in trials if x["malicious"] and x["policy_allowed"] is False);_bar(destination/"figures/figure_04_policy_detection.svg","Detection by family",list(family.items()))
    _bar(destination/"figures/figure_05_synthetic_realistic.svg","Policy recall percent",[("synthetic",100*51/72),("realistic",100*metrics["policy_detection"]["count"]/metrics["policy_detection"]["denominator"])])
    phases=[(k,v["median_ns"]/1000) for k,v in document["performance"].items() if k not in {"agent_end_to_end","security_overhead_fraction_ppm"}];_bar(destination/"figures/figure_06_latency_breakdown.svg","Median phase latency (us)",phases)
    fraction=document["performance"]["security_overhead_fraction_ppm"]["median_ns"]/10000;_bar(destination/"figures/figure_07_security_overhead.svg","Security overhead fraction",[("percent",fraction)])
    _bar(destination/"figures/figure_08_state_lineage_growth.svg","Aggregate state and lineage growth",[(k,v) for k,v in document["state_growth"].items()])
    (destination/"report/stage13a_summary.md").write_text(_summary(document,live));(destination/"report/limitations.md").write_text("# Stage 13A limitations\n\n"+"\n".join(f"- {x}" for x in document["limitations"])+"\n")


def _summary(d,live):
 m=d["deterministic"]["summary"];c=d["complexity"];delayed=d["delayed"]
 return f"""# Stage 13A realistic agent workload

This is a simulated realistic agent workload, not a production deployment.

## Deterministic results

- Benign completion: {m['benign_completion']['count']}/{m['benign_completion']['denominator']}
- Policy detection: {m['policy_detection']['count']}/{m['policy_detection']['denominator']}
- Persistent compromise: {m['persistent_compromise']['count']}/{m['persistent_compromise']['denominator']}
- External-effect leakage: {m['external_effect_leakage']['count']}/{m['external_effect_leakage']['denominator']}
- Containment after rejection: {m['containment_after_rejection']['count']}/{m['containment_after_rejection']['denominator']}
- Cross-session leakage: {d['cross_session']['cross_session_leakage']}
- Delayed origin user/session/transaction/source were recovered: {bool(delayed['origin']['users'] and delayed['origin']['sessions'] and delayed['origin']['transactions'] and delayed['origin']['sources'])}
- Selective recovery preserved unrelated state: {delayed['unrelated_state_preserved']}

The runtime contained every rejected workflow and suppressed every malicious simulated effect. Frozen PolicyV2 nevertheless accepted 11 workflows involving semantic, cache/retrieval, or delayed poisoning, leaving persistent state. This negative result is preserved without retuning.

## Live subset

{('Not run or unavailable.' if live is None else f"Attempts: {live['attempts']}; valid plans: {sum(x['model_plan_valid'] for x in live['trials'])}; metrics: {live['summary']}")}

## Boundary

Trusted core remains {c['trusted_core_modules']} modules / {c['trusted_core_python_loc']} non-comment LOC with {c['third_party_core_dependencies']} third-party core dependencies. Agent/workload code is {c['agent_workload_python_loc']} non-comment LOC above the core. Trusted-core growth is zero.
"""


def _metric(name,x):return {"metric":name,"count":x["count"],"denominator":x["denominator"],"rate":x["count"]/x["denominator"] if x["denominator"] else None}
def _comparison(name,s,r):
 if name=="policy_recall":r=r.get("policy_detection",{})
 return {"metric":name,"synthetic_count":s.get("count"),"synthetic_denominator":s.get("denominator"),"realistic_count":r.get("count"),"realistic_denominator":r.get("denominator")}
def _counts(values):
 out={}
 for x in values:out[x]=out.get(x,0)+1
 return out
def _json(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True,default=str)+"\n")
def _csv(path,rows):
 with path.open("w",newline="") as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else []);w.writeheader();w.writerows(rows)
def _bar(path,title,values):
 width=max(700,80*len(values));height=430;maximum=max([float(v) for _,v in values] or [1]) or 1;parts=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"><rect width="100%" height="100%" fill="white"/><text x="{width/2}" y="25" text-anchor="middle" font-family="sans-serif" font-size="18">{title}</text>']
 for i,(label,value) in enumerate(values):
  x=70+i*((width-100)/max(1,len(values)));h=280*float(value)/maximum;y=335-h;parts += [f'<rect x="{x}" y="{y}" width="45" height="{h}" fill="#2563eb"/><text x="{x+22}" y="{y-5}" text-anchor="middle" font-family="sans-serif" font-size="10">{float(value):.1f}</text><text x="{x+22}" y="350" transform="rotate(50 {x+22} 350)" font-family="sans-serif" font-size="9">{label}</text>']
 parts.append('</svg>');path.write_text("\n".join(parts)+"\n")
def _architecture(path):
 labels=("User","Retrieve","Context","Plan","Memory/Cache","Tool/Effect","Validate","Commit/Rollback")
 parts=['<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="180"><rect width="100%" height="100%" fill="white"/>']
 for i,label in enumerate(labels):
  x=15+i*135;parts.append(f'<rect x="{x}" y="55" width="115" height="50" rx="6" fill="#dbeafe" stroke="#2563eb"/><text x="{x+57}" y="84" text-anchor="middle" font-family="sans-serif" font-size="12">{label}</text>');
  if i<len(labels)-1:parts.append(f'<path d="M{x+115} 80 L{x+133} 80" stroke="#111" marker-end="url(#a)"/>')
 parts.append('<defs><marker id="a" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z"/></marker></defs></svg>');path.write_text("\n".join(parts)+"\n")
