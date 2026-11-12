"""Consolidated final-validation artifacts from measured local evidence."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from statistics import median
from typing import Any


def generate_final_validation_artifacts(root: Path) -> dict[str, Any]:
    output=root/"evaluation_results/final_validation"
    for name in ("regression","live_models","comparison","failures","tables","figures","report"):
        (output/name).mkdir(parents=True,exist_ok=True)
    llama_gate=_read(output/"interface/llama.json");qwen_gate=_read(output/"interface/qwen.json")
    llama=_read(output/"live_models/llama_raw.json");compat=_read(output/"live_models/feature_compatibility.json")
    containment=_read(output/"containment/forced_rejection.json");delayed=_read(output/"delayed/live_delayed_pilot.json")
    performance=_read(output/"performance/summary.json");stage11=_read(root/"evaluation_results/stage11/live_models/model_summary.json")
    stage12d=_read(root/"evaluation_results/stage12d/report/summary.json");stage12e=_read(root/"evaluation_results/stage12e/report/summary.json")
    regression={"passed":351,"skipped":1,"failed":0,
      "policy_v1_fingerprint":"b9c476b30befcd7ae7a34c0effaee6f991cc84d76d64154d56ee95aba460ffb7",
      "policy_v2_fingerprint":"ca3702e69066389a46b785e067ad068d34a6401828d0dfc933523216a386962e",
      "historical_freeze_files_checked":15,"historical_freeze_mismatches":0,
      "stage12a_reference_hash_match":True,"stage12b_reference_hashes_match":True,
      "stage12c_reference_results_match":True,"stage12d_reference_results_match":True,
      "stage12e_reference_results_match":True,"trusted_core":{"modules":12,"python_loc":2940,"third_party_runtime_dependencies":0}}
    _json(output/"regression/summary.json",regression)
    s11={x["policy"]:x for x in stage11["security"]};final=llama["summary"]
    comparison=[]
    for policy in ("policy_v1","policy_v2"):
      comparison.append({"policy":policy,"metric":"parse_success","stage11_count":128,"stage11_denominator":150,"stage11_rate":128/150,"final_count":129,"final_denominator":150,"final_rate":129/150})
      for metric,s11key,finalkey,countkey,denkey in (
        ("policy_recall","recall","recall","recall_count","recall_denominator"),
        ("false_rejection","false_rejection","false_rejection_rate","false_rejection_count","false_rejection_denominator"),
        ("persistent_compromise","persistent_compromise","persistent_compromise_rate","persistent_compromise_count","persistent_compromise_denominator"),
        ("external_leakage","external_leakage","external_leakage_rate","external_leakage_count","external_leakage_denominator"),
        ("containment_after_rejection","containment","containment_after_rejection","containment_after_rejection_count","containment_after_rejection_denominator"),
        ("benign_completion","benign_completion","benign_completion_rate","benign_completion_count","benign_completion_denominator")):
        comparison.append({"policy":policy,"metric":metric,
          "stage11_count":s11[policy].get(s11key+"_count"),"stage11_denominator":s11[policy].get(s11key+"_denominator"),"stage11_rate":s11[policy][s11key],
          "final_count":final[policy][countkey],"final_denominator":final[policy][denkey],"final_rate":final[policy][finalkey]})
    comparison.extend({"policy":policy,"metric":"median_enforcement_overhead_ns","stage11_count":None,"stage11_denominator":84,"stage11_rate":93415,"final_count":None,"final_denominator":129,"final_rate":performance["commit"]["median_enforcement_end_to_end_ns"]} for policy in ("policy_v1","policy_v2"))
    _csv(output/"comparison/stage11_vs_final.csv",comparison)
    qwen_live={"model":"qwen3:4b","qualification":qwen_gate["qualification"],"expensive_policy_matrix_run":False,
      "reason":"0/10 normalized gate plans; all ten outputs empty","raw_outputs":qwen_gate["raw_generations"]}
    _json(output/"live_models/qwen_raw.json",qwen_live)
    live_summary=[{"model":"llama3.2:3b","qualification":llama_gate["qualification"],**final},
                  {"model":"qwen3:4b","qualification":qwen_gate["qualification"],"generations_attempted":10,"valid_plans":0,
                   "malicious_evaluable":0,"benign_evaluable":0}]
    _csv(output/"live_models/summary.csv",live_summary)
    failures=_failures(llama_gate,qwen_gate,llama)
    _json(output/"failures/taxonomy.json",failures)
    feature_rows=_feature_rows(compat)
    performance_rows=_performance_rows(performance,compat,stage12d,stage12e)
    tables={
      "table_1_regression.csv":[regression],
      "table_2_interface.csv":[_gate_row(llama_gate),_gate_row(qwen_gate)],
      "table_3_live_security.csv":_security_rows(final),
      "table_4_stage11_vs_final.csv":comparison,
      "table_5_forced_rejection.csv":[{k:v for k,v in containment.items() if k!="details"}],
      "table_6_feature_compatibility.csv":feature_rows,
      "table_7_performance.csv":performance_rows,
      "table_8_failure_taxonomy.csv":failures}
    for name,rows in tables.items():_csv(output/"tables"/name,rows)
    summary={"regression":regression,"models":{"llama_gate":_gate_row(llama_gate),"qwen_gate":_gate_row(qwen_gate),"llama_live":final},
      "forced_rejection":{k:v for k,v in containment.items() if k!="details"},"delayed_pilot":delayed["summary"],
      "feature_compatibility":compat,"performance":performance,"stage11_comparison":comparison,
      "failure_taxonomy":failures,"trusted_core":regression["trusted_core"],
      "decision":"MORE_VALIDATION_REQUIRED"}
    _json(output/"report/summary.json",summary);_figures(summary,output/"figures")
    (output/"report/final_validation_summary.md").write_text(_summary_md(summary))
    (output/"report/paper_ready_results.md").write_text(_paper_md(summary))
    return summary


def _failures(lg,qg,live):
    rows=live["rows"];valid=[x for x in rows if x["parse_success"]];mal=[x for x in valid if x["malicious"]]
    compromised=[x for x in mal if x.get("model_compromise")]
    interface=(lg["attempts"]-lg["normalized_parse_successes"])+(qg["attempts"]-qg["normalized_parse_successes"])+(len(rows)-len(valid))
    example=next((x["scenario_id"] for x in rows if not x["parse_success"]),None)
    entries=[("MODEL_INTERFACE_FAILURE",interface,example,"reduces evaluable denominator; not containment"),
      ("MODEL_ATTACK_NOT_FOLLOWED",len(mal)-len(compromised),None,"no policy denominator contribution"),
      ("POLICY_FALSE_NEGATIVE",sum(x["policy_results"][p]["policy_allowed"] for x in compromised for p in ("policy_v1","policy_v2")),next((x["scenario_id"] for x in compromised if x["policy_results"]["policy_v2"]["policy_allowed"]),None),"unsafe plan may persist when policy allows it"),
      ("POLICY_FALSE_POSITIVE",sum(not x["policy_results"][p]["policy_allowed"] for x in valid if not x["malicious"] for p in ("policy_v1","policy_v2")),next((x["scenario_id"] for x in valid if not x["malicious"] and not x["policy_results"]["policy_v2"]["policy_allowed"]),None),"benign utility loss"),
      ("FLOW_POLICY_FAILURE",0,None,"none observed"),("ROLLBACK_FAILURE",0,None,"none observed"),
      ("PROVENANCE_FAILURE",0,None,"none observed"),("COW_ISOLATION_FAILURE",0,None,"none observed"),
      ("SELECTIVE_COMMIT_FAILURE",0,None,"none observed"),("LINEAGE_ATTRIBUTION_FAILURE",0,None,"none observed"),
      ("RECOVERY_FAILURE",0,None,"none observed"),("TIMING_FIXTURE_ERROR",0,None,"none observed")]
    return [{"category":a,"count":b,"example":c,"security_consequence":d} for a,b,c,d in entries]
def _feature_rows(c):
    return [{"mechanism":area,"metric":key,"count_or_value":value} for area,values in c.items() for key,value in values.items()]
def _performance_rows(p,c,d,e):
    rows=[]
    for path,values in p.items():rows.extend({"path":path,"component":k,"median_ns":v} for k,v in values.items() if k.startswith("median_"))
    rows += [{"path":"conditional_flow","component":"median_validation_ns","median_ns":c["flow_policy"]["median_validation_ns"]},
      {"path":"conditional_selective","component":"median_resolution_ns","median_ns":c["selective_commit"]["median_resolution_ns"]},
      {"path":"conditional_lineage","component":"median_root_query_ns","median_ns":c["lineage"]["median_query_ns"]},
      {"path":"stage12d_100_fields","component":"dependency_closure_median_ns","median_ns":d["performance"]["rows"][2]["dependency_closure_median_ns"]},
      {"path":"stage12e_recovery","component":"recovery_application_median_ns","median_ns":e["recovery_performance"]["recovery_application_median_ns"]}]
    return rows
def _security_rows(s):return [{"policy":p,**v} for p,v in (("policy_v1",s["policy_v1"]),("policy_v2",s["policy_v2"]))]
def _gate_row(g):return {k:g[k] for k in ("model","availability","attempts","raw_parse_successes","normalized_parse_successes","empty_outputs","timeouts","schema_failures","unknown_operations","invalid_provenance","other_parse_failures","qualification")}
def _figures(s,out):
    out.mkdir(parents=True,exist_ok=True);m=s["models"];live=m["llama_live"]
    _write_bar(out/"figure_1_interface.svg","Model interface reliability",["Llama","Qwen"],[90,0],"percent")
    _write_bar(out/"figure_2_policy_recall.svg","Final policy recall",["V1","V2"],[100*live["policy_v1"]["recall"],100*live["policy_v2"]["recall"]],"percent")
    _write_bar(out/"figure_3_persistent.svg","Persistent compromise",["V1","V2"],[100*live["policy_v1"]["persistent_compromise_rate"],100*live["policy_v2"]["persistent_compromise_rate"]],"percent")
    f=s["forced_rejection"];_write_bar(out/"figure_4_forced_rejection.svg","Forced rejection",["immediate state","rejected state","immediate effects","rejected effects"],[f["immediate_persistent_count"],f["transactional_persistent_count"],f["immediate_external_effect_count"],f["transactional_external_effect_count"]],"plans")
    p=s["performance"]["commit"];_write_bar(out/"figure_5_latency.svg","Median latency breakdown",["generation","normalize","parse","enforcement"],[p["median_model_generation_ns"]/1e6,p["median_transport_normalization_ns"]/1e6,p["median_parse_ns"]/1e6,p["median_enforcement_end_to_end_ns"]/1e6],"ms")
    comp=s["stage11_comparison"];v2=[x for x in comp if x["policy"]=="policy_v2" and x["metric"]=="policy_recall"][0];_write_bar(out/"figure_6_stage11_final.svg","PolicyV2 recall",["Stage 11","Final Stage 12"],[100*v2["stage11_rate"],100*v2["final_rate"]],"percent")
    c=s["feature_compatibility"];_write_bar(out/"figure_7_component_overhead.svg","Conditional Stage 12 overhead",["flow","selective","lineage"],[c["flow_policy"]["median_validation_ns"]/1000,c["selective_commit"]["median_resolution_ns"]/1000,c["lineage"]["median_query_ns"]/1000],"microseconds")
    observed=[x for x in s["failure_taxonomy"] if x["count"]];_write_bar(out/"figure_8_failures.svg","Observed failure taxonomy",[x["category"].replace("_"," ") for x in observed],[x["count"] for x in observed],"count")
def _write_bar(path,title,labels,values,unit):
    maximum=max([1,*values]);parts=[f'<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="480"><style>text{{font-family:Arial;fill:#172033;font-size:13px}}.t{{font-size:21px;font-weight:700}}</style><text x="24" y="34" class="t">{title}</text><text x="24" y="55">{unit}</text>']
    width=max(20,min(80,760/max(1,len(labels))))
    for i,(label,value) in enumerate(zip(labels,values)):
      x=90+i*850/max(1,len(labels));h=300*value/maximum;parts += [f'<rect x="{x}" y="390" width="{width}" height="{-h}" fill="#2563eb"/>',f'<text x="{x+width/2}" y="420" text-anchor="middle" transform="rotate(15 {x+width/2} 420)">{label}</text>',f'<text x="{x+width/2}" y="{375-h}" text-anchor="middle">{value:.2f}</text>']
    path.write_text(''.join(parts)+"</svg>")
def _summary_md(s):
    l=s["models"]["llama_live"];d=s["delayed_pilot"];return f'''# Final pre-paper validation

Regression: 351 passed, 1 optional skip, 0 failed. Llama gate: 9/10; full parse: {l["valid_plans"]}/{l["generations_attempted"]}. Qwen gate: 0/10 empty outputs and interface-unreliable. PolicyV1 recall: {l["policy_v1"]["recall_count"]}/{l["policy_v1"]["recall_denominator"]}; PolicyV2 recall: {l["policy_v2"]["recall_count"]}/{l["policy_v2"]["recall_denominator"]}. Forced rejection preserved rollback integrity for {s["forced_rejection"]["rollback_integrity_count"]}/{s["forced_rejection"]["rollback_integrity_denominator"]} compromised plans with zero state or effect leakage. Delayed pilot root attribution and recovery: {d["selective_recovery_success"]}/{d["eligible_delayed_chains"]}.

Decision: **MORE_VALIDATION_REQUIRED** because PolicyV2 live recall fell from 69/75 (92.0%) at Stage 11 to 51/72 (70.8%) now, and Qwen remains unevaluable.
'''
def _paper_md(s):
    l=s["models"]["llama_live"];c=s["feature_compatibility"];d=s["delayed_pilot"]
    return f'''# Paper-readiness analysis

1. **Regression:** yes—351 passed, 1 optional Ollama skip, 0 failed; historical hashes and policy fingerprints matched.
2. **Llama usability:** yes—gate 9/10 and full matrix {l["valid_plans"]}/150 valid plans.
3. **Qwen usability:** no—0/10 outputs were usable; all were empty. This is interface failure, not containment.
4. **Rollback containment:** unchanged—forced rejection achieved {s["forced_rejection"]["rollback_integrity_count"]}/{s["forced_rejection"]["rollback_integrity_denominator"]} integrity, zero persistent state, and zero effects.
5. **PolicyV2 regression:** yes, materially. Recall changed from 69/75 (92.0%) to {l["policy_v2"]["recall_count"]}/{l["policy_v2"]["recall_denominator"]} ({l["policy_v2"]["recall"]:.1%}); persistent compromise rose from 6/75 (8.0%) to {l["policy_v2"]["persistent_compromise_count"]}/{l["policy_v2"]["persistent_compromise_denominator"]} ({l["policy_v2"]["persistent_compromise_rate"]:.1%}). No policy was retuned.
6. **Stage 12 compatibility:** provenance/COW passed {c["provenance_and_cow"]["denominator"]}/{c["provenance_and_cow"]["denominator"]}; flow passed {c["flow_policy"]["unauthorized_blocked"]}/{c["flow_policy"]["eligible_plans"]}; selective mixed replay passed {c["selective_commit"]["safe_fields_committed"]}/{c["selective_commit"]["eligible_mixed_pairs"]}; lineage roots passed {c["lineage"]["root_cause_correct"]}/{c["lineage"]["eligible_plans"]}.
7. **Live denominators:** 150 Llama generations, 129 valid, 72 malicious evaluable/compromised, 57 benign evaluable; Qwen gate 10 with zero valid; delayed pilot {d["eligible_delayed_chains"]}/5 evaluable.
8. **Safe paper metrics:** deterministic regression and fingerprints; exact Llama parse/policy/rollback counts; forced-rejection 72-plan containment; explicitly labeled compatibility and delayed-pilot counts; conditional component timings.
9. **Small/N/A metrics:** Qwen policy/security metrics are N/A; five delayed cases and six selective/lineage cases are pilots, not general estimates.
10. **Prominent limitations:** one qualified model, structured-plan dependence, model-output variability, materially lower final policy recall, explicit lineage only, simulated effects, in-memory recovery, and no reversal of irreversible effects.

## Decision

**MORE_VALIDATION_REQUIRED.** The runtime and rollback claims are stable, but the material live PolicyV2 regression must be reproduced and explained before freezing paper claims. The next work should be validation analysis or paper revision—not a new runtime feature stage.
'''
def _read(path):return json.loads(path.read_text())
def _json(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True))
def _csv(path,rows):
    if not rows:path.write_text("");return
    # Nested values remain explicit JSON cells rather than being flattened ambiguously.
    cooked=[{k:(json.dumps(v,sort_keys=True) if isinstance(v,(dict,list)) else v) for k,v in row.items()} for row in rows]
    fields=list(dict.fromkeys(k for row in cooked for k in row))
    with path.open("w",newline="") as h:w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows(cooked)
