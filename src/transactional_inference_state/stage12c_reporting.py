"""Generate dependency-free Stage 12C research artifacts from measured data."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from statistics import median
from typing import Any


def generate_stage12c_artifacts(document: dict[str, Any], output: Path) -> dict[str, Any]:
    for name in ("flow_policy", "flagship", "concurrency", "performance",
                 "tables", "figures", "report"):
        (output / name).mkdir(parents=True, exist_ok=True)
    trials=document["flow_trials"];policy_unauthorized=[x for x in trials if not x["expected_authorized"] and x["outcome"]!="TRANSACTION_ISOLATION"]
    authorized=[x for x in trials if x["expected_authorized"]]
    blocked=sum(not x["policy_allowed"] for x in policy_unauthorized);leaked=sum(x["leaked"] for x in policy_unauthorized);false_blocks=sum(x["false_block"] for x in authorized)
    flow_summary={
        "flow_policy_trials":len(policy_unauthorized)+len(authorized),
        "unauthorized_cross_session_attempts":len(policy_unauthorized),
        "unauthorized_flows_blocked":blocked,"unauthorized_flows_allowed":leaked,
        "valid_flows":len(authorized),"valid_flows_false_blocked":false_blocks,
        "cross_session_leakage_rate":leaked/len(policy_unauthorized),
        "flow_policy_recall":blocked/len(policy_unauthorized),
        "flow_policy_precision":blocked/max(1,blocked+false_blocks),
        "flow_false_positive_rate":false_blocks/max(1,len(authorized)),
        "dirty_reads_prevented_by_transaction_isolation":sum(x["outcome"]=="TRANSACTION_ISOLATION" and not x["leaked"] for x in trials),
    }
    _json(output/"flow_policy/raw_results.json",trials);_json(output/"flow_policy/summary.json",flow_summary)
    _json(output/"flagship/mixed_field_flow.json",document["mixed_field"])
    _json(output/"flagship/declassification.json",{"before":document["mixed_field"]["before_outcomes"],"after":document["mixed_field"]["after_outcomes"],"provenance_unchanged":document["mixed_field"]["provenance_unchanged"]})
    _json(output/"flagship/label_stripping.json",document["label_stripping"]);_json(output/"flagship/laundering.json",document["laundering"])
    _json(output/"concurrency/raw_results.json",document["concurrency"]);_csv(output/"concurrency/summary.csv",_stress_summary(document["concurrency"]))
    _json(output/"performance/flow_overhead.json",document["overhead"])
    _csv(output/"tables/table_1_flow_metrics.csv",[flow_summary]);_csv(output/"tables/table_2_attack_trials.csv",trials);_csv(output/"tables/table_3_concurrency.csv",_stress_summary(document["concurrency"]));_csv(output/"tables/table_4_overhead.csv",[document["overhead"]])
    summary={"flow_policy":flow_summary,"mixed_field":document["mixed_field"],"concurrency":_stress_summary(document["concurrency"]),"overhead":document["overhead"],"complexity":document["complexity"],"interpretation":{"conflict_aborts_counted_as_policy_blocks":False,"dirty_reads_counted_as_policy_blocks":False,"stress_repetitions_per_scale":3}}
    _json(output/"report/summary.json",summary);(output/"report/stage12c_summary.md").write_text(_report(summary));(output/"report/limitations.md").write_text("# Stage 12C limitations\n\nHandcrafted deterministic attacks; one authorized corpus field; in-memory threads under the Python runtime; no durable or distributed enforcement; explicit rather than inferred lineage; exact field-scope declassification; flat shared JSON filtering; key-level shared conflicts; throughput and latency are local measurements, not production capacity.\n")
    _figures(document,flow_summary,output/"figures")
    return summary


def _stress_summary(rows:list[dict[str,Any]])->list[dict[str,Any]]:
    result=[]
    for count in sorted({x["sessions"] for x in rows}):
        selected=[x for x in rows if x["sessions"]==count]
        result.append({"sessions":count,"runs":len(selected),"total_transactions":sum(x["total_transactions"] for x in selected),"completed_transactions":sum(x["completed_transactions"] for x in selected),"flow_decisions":sum(x["flow_decisions"] for x in selected),"blocked_flows":sum(x["blocked_flows"] for x in selected),"declassified_flows_allowed":sum(x["allowed_declassified_flows"] for x in selected),"public_flows_allowed":sum(x["public_flows_allowed"] for x in selected),"unauthorized_flows_allowed":sum(x["unauthorized_flows_allowed"] for x in selected),"false_blocks":sum(x["valid_flows_false_blocked"] for x in selected),"conflict_aborts":sum(x["conflict_aborts"] for x in selected),"rollback_integrity":all(x["rollback_integrity"] for x in selected),"median_run_throughput":median(x["throughput_transactions_per_second"] for x in selected),"median_request_latency_ns":median(x["median_latency_ns"] for x in selected),"median_run_p95_latency_ns":median(x["p95_latency_ns"] for x in selected)})
    return result


def _figures(doc:dict[str,Any],metrics:dict[str,Any],out:Path)->None:
    out.mkdir(parents=True,exist_ok=True);(out/"figure_1_flow_architecture.svg").write_text(_architecture())
    families={}
    for row in doc["flow_trials"]:
        if row["outcome"]=="TRANSACTION_ISOLATION":continue
        item=families.setdefault(row["attack_family"],[0,0]);item[0]+=int(row["policy_allowed"]);item[1]+=int(not row["policy_allowed"])
    (out/"figure_2_family_decisions.svg").write_text(_bars("Allowed vs denied by family",list(families),[v[0] for v in families.values()],[v[1] for v in families.values()],"allowed","denied"))
    mixed=doc["mixed_field"];(out/"figure_3_mixed_fields.svg").write_text(_bars("Mixed-field filtering",["display_name","private_token","weather"],[int(x in mixed["before_value"]) for x in ("display_name","private_token","weather")],[int(x not in mixed["before_value"]) for x in ("display_name","private_token","weather")],"allowed","filtered"))
    (out/"figure_4_declassification.svg").write_text(_bars("Display name before/after declassification",["before","after"],[0,1],[1,0],"allowed","denied"))
    (out/"figure_5_leakage.svg").write_text(_bars("Unauthorized cross-session flows",["blocked","leaked"],[metrics["unauthorized_flows_blocked"],metrics["unauthorized_flows_allowed"]],[0,0],"count",""))
    stress=_stress_summary(doc["concurrency"]);labels=[str(x["sessions"]) for x in stress]
    (out/"figure_6_throughput.svg").write_text(_line("Median run throughput",labels,[x["median_run_throughput"] for x in stress],"transactions/s"))
    (out/"figure_7_p95_latency.svg").write_text(_line("Median run P95 flow latency",labels,[x["median_run_p95_latency_ns"]/1e3 for x in stress],"microseconds"))
    overhead=doc["overhead"]
    (out/"figure_8_flow_overhead.svg").write_text(_line("Field-read and flow-check cost",["baseline","provenance","same","denied","declassified"],[overhead["baseline_field_read_median_ns"]/1e3,overhead["provenance_field_read_median_ns"]/1e3,overhead["same_session_check_median_ns"]/1e3,overhead["cross_session_denied_median_ns"]/1e3,overhead["cross_session_declassified_median_ns"]/1e3],"microseconds"))


def _start(title:str)->str:return f'<svg xmlns="http://www.w3.org/2000/svg" width="900" height="440" viewBox="0 0 900 440" role="img" aria-label="{title}"><style>text{{font-family:Arial,sans-serif;fill:#172033;font-size:13px}}.t{{font-size:20px;font-weight:700}}.a{{stroke:#475569;stroke-width:1.5;fill:none}}</style>'
def _bars(title,labels,one,two,name1,name2):
    maxv=max([1,*one,*two]);w=max(18,min(50,600/max(1,len(labels))/2));parts=[_start(title),f'<text x="20" y="32" class="t">{title}</text>']
    for i,label in enumerate(labels):
        x=70+i*760/max(1,len(labels));h1=280*one[i]/maxv;h2=280*two[i]/maxv;parts += [f'<rect x="{x}" y="{370-h1}" width="{w}" height="{h1}" fill="#2563eb"/>',f'<rect x="{x+w+3}" y="{370-h2}" width="{w}" height="{h2}" fill="#b45309"/>',f'<text x="{x+w}" y="392" text-anchor="middle" transform="rotate(25 {x+w} 392)">{label}</text>']
    parts.append(f'<text x="720" y="30">blue={name1}; orange={name2}</text></svg>');return ''.join(parts)
def _line(title,labels,values,unit):
    maxv=max(values) or 1;parts=[_start(title),f'<text x="20" y="32" class="t">{title}</text><text x="20" y="52">{unit}</text><path d="M80 70 V370 H820" class="a"/>'];points=[]
    for i,(label,value) in enumerate(zip(labels,values)):
        x=80+i*740/max(1,len(labels)-1);y=370-280*value/maxv;points.append(f'{x},{y}');parts += [f'<circle cx="{x}" cy="{y}" r="4" fill="#15803d"/>',f'<text x="{x}" y="395" text-anchor="middle">{label}</text>',f'<text x="{x}" y="{y-8}" text-anchor="middle">{value:.3f}</text>']
    parts.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="#15803d" stroke-width="2.5"/></svg>');return ''.join(parts)
def _architecture():return _start("Cross-session flow decision architecture")+'''<text x="20" y="32" class="t">Cross-session field flow</text><rect x="40" y="100" width="180" height="70" rx="7" fill="#fee2e2" stroke="#334155"/><text x="130" y="130" text-anchor="middle">Session A value</text><text x="130" y="150" text-anchor="middle">authoritative provenance</text><path d="M220 135 H320" class="a"/><rect x="320" y="90" width="220" height="90" rx="7" fill="#dbeafe" stroke="#334155"/><text x="430" y="122" text-anchor="middle">Shared field metadata</text><text x="430" y="145" text-anchor="middle">origin retained</text><path d="M540 135 H640" class="a"/><rect x="640" y="90" width="210" height="90" rx="7" fill="#fef3c7" stroke="#334155"/><text x="745" y="120" text-anchor="middle">FlowPolicy</text><text x="745" y="143" text-anchor="middle">principal + roots + scope</text><text x="745" y="163" text-anchor="middle">+ declassification</text><path d="M745 180 V250" class="a"/><rect x="560" y="250" width="150" height="60" rx="7" fill="#fee2e2" stroke="#334155"/><text x="635" y="285" text-anchor="middle">FILTER / DENY</text><rect x="750" y="250" width="120" height="60" rx="7" fill="#dcfce7" stroke="#334155"/><text x="810" y="285" text-anchor="middle">ALLOW</text></svg>'''
def _report(s):
    f=s["flow_policy"];return f'''# Stage 12C measured summary

Flow-policy unauthorized attempts: {f["unauthorized_cross_session_attempts"]}; blocked: {f["unauthorized_flows_blocked"]}; leaked: {f["unauthorized_flows_allowed"]}. Valid flows: {f["valid_flows"]}; false blocks: {f["valid_flows_false_blocked"]}. Dirty reads prevented by transaction isolation: {f["dirty_reads_prevented_by_transaction_isolation"]} (not counted as policy blocks).

Across three repetitions at 10, 25, 50, and 100 sessions, see `../concurrency/summary.csv`. Conflict aborts are not counted as information-flow decisions.
'''
def _json(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True))
def _csv(path,rows):
    if not rows:path.write_text("");return
    with path.open("w",newline="") as h:w=csv.DictWriter(h,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
