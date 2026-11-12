"""Generate Stage 12E tables, reports, and dependency-free SVG figures."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from statistics import median
from typing import Any


def generate_stage12e_artifacts(document: dict[str, Any], output: Path) -> dict[str, Any]:
    for name in ("flagship", "corpus", "recovery", "graph", "tables", "figures", "report"):
        (output / name).mkdir(parents=True, exist_ok=True)
    flagship, corpus = document["flagship"], document["corpus"]
    _json(output / "flagship/delayed_compromise.json", flagship)
    _json(output / "flagship/lineage.json", flagship["graph"])
    _json(output / "flagship/recovery_plan.json", flagship["recovery_plan"])
    _json(output / "corpus/raw_results.json", corpus["trials"])
    _json(output / "corpus/summary.json", corpus["summary"])
    _json(output / "recovery/precision_recall.json", {
        key: corpus["summary"][key] for key in (
            "contamination_precision", "contamination_recall", "contamination_f1",
            "over_quarantine_rate", "under_recovery_rate", "denominators")})
    _json(output / "recovery/state_preservation.json", {
        "recovery_success": corpus["summary"]["recovery_success"],
        "unrelated_state_preservation": corpus["summary"]["unrelated_state_preservation"],
        "post_recovery_leakage": corpus["summary"]["post_recovery_leakage"],
        "flagship": {"unrelated_state_preserved": flagship["unrelated_state_preserved"],
                     "post_recovery_reads_blocked": flagship["post_recovery_reads_blocked"]}})
    _json(output / "graph/growth.json", document["growth"])
    _json(output / "graph/query_performance.json", {
        "growth_queries": document["growth"]["rows"],
        "recovery_operations": document["recovery_performance"]})
    _csv(output / "tables/table_1_corpus_metrics.csv", [corpus["summary"]])
    _csv(output / "tables/table_2_delayed_trials.csv", corpus["trials"])
    _csv(output / "tables/table_3_graph_growth.csv", document["growth"]["rows"])
    _csv(output / "tables/table_4_recovery_performance.csv", [document["recovery_performance"]])
    _json(output / "report/summary.json", document)
    (output / "report/stage12e_summary.md").write_text(_report(document))
    (output / "report/limitations.md").write_text(
        "# Stage 12E limitations\n\nAll dependencies are explicitly registered; no semantic or causal "
        "inference is performed. The lineage graph, quarantine, invalidation markers, and audit log "
        "are process-local. Recovery does not undo historical commits or executed irreversible effects. "
        "The 25-scenario corpus is handcrafted, graph branches are controlled, and perfect controlled-set "
        "scores are not deployment estimates. Graph storage grows without compaction. The 10,000-node "
        "measurements are local Python microbenchmarks.\n")
    _figures(document, output / "figures")
    return document


def _figures(doc, out):
    out.mkdir(parents=True, exist_ok=True); f=doc["flagship"]; trials=doc["corpus"]["trials"]; s=doc["corpus"]["summary"]
    (out/"figure_1_t1_t8_lineage.svg").write_text(_lineage(f))
    families=sorted({x["attack_family"] for x in trials})
    (out/"figure_2_attribution_family.svg").write_text(_bars("Root-cause attribution by family",families,[100*sum(x["root_cause_found"] for x in trials if x["attack_family"]==family)/sum(x["attack_family"]==family for x in trials) for family in families],"percent"))
    (out/"figure_3_precision_recall.svg").write_text(_bars("Contamination tracing",["precision","recall","F1"],[100*s[x] for x in ("contamination_precision","contamination_recall","contamination_f1")],"percent"))
    (out/"figure_4_recovery_success.svg").write_text(_bars("Recovery success",["success","failure"],[s["recovery_success"],s["delayed_attack_count"]-s["recovery_success"]],"trials"))
    (out/"figure_5_state_preservation.svg").write_text(_bars("Unrelated-state preservation",["preserved","incorrectly marked"],[100*s["unrelated_state_preservation"],100*(1-s["unrelated_state_preservation"])],"percent"))
    (out/"figure_6_over_under.svg").write_text(_bars("Recovery error rates",["over-quarantine","under-recovery"],[100*s["over_quarantine_rate"],100*s["under_recovery_rate"]],"percent"))
    growth=doc["growth"]["rows"]; labels=[str(x["nodes"]) for x in growth]
    (out/"figure_7_graph_growth.svg").write_text(_line("Estimated graph storage",labels,[x["estimated_bytes"]/1024 for x in growth],"KiB"))
    (out/"figure_8_query_latency.svg").write_text(_line("Root-cause query latency",labels,[x["root_cause_query_median_ns"]/1e6 for x in growth],"milliseconds"))
    delays=sorted({x["delay_transactions"] for x in trials})
    (out/"figure_9_delay_attribution.svg").write_text(_line("Delay vs attribution success",[str(x) for x in delays],[100*sum(t["root_cause_found"] for t in trials if t["delay_transactions"]==x)/sum(t["delay_transactions"]==x for t in trials) for x in delays],"percent"))
    (out/"figure_10_recovery_architecture.svg").write_text(_architecture())


def _start(title): return f'<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="480" viewBox="0 0 1000 480" role="img" aria-label="{title}"><style>text{{font-family:Arial;fill:#172033;font-size:13px}}.t{{font-size:21px;font-weight:700}}.a{{stroke:#475569;stroke-width:2;fill:none}}</style><text x="24" y="34" class="t">{title}</text>'
def _bars(title,labels,values,unit):
    maximum=max([1,*values]);parts=[_start(title),f'<text x="24" y="56">{unit}</text>'];width=max(12,min(55,720/max(1,len(labels))))
    for i,(label,value) in enumerate(zip(labels,values)):
        x=80+i*850/max(1,len(labels));h=300*value/maximum;parts += [f'<rect x="{x}" y="390" width="{width}" height="{-h}" fill="#2563eb"/>',f'<text x="{x+width/2}" y="420" text-anchor="middle" transform="rotate(20 {x+width/2} 420)">{label}</text>',f'<text x="{x+width/2}" y="{375-h}" text-anchor="middle">{value:.1f}</text>']
    return ''.join(parts)+"</svg>"
def _line(title,labels,values,unit):
    maximum=max(values) or 1;parts=[_start(title),f'<text x="24" y="56">{unit}</text><path d="M80 75 V390 H930" class="a"/>'];points=[]
    for i,(label,value) in enumerate(zip(labels,values)):
        x=100+i*800/max(1,len(labels)-1);y=380-280*value/maximum;points.append(f"{x},{y}");parts += [f'<circle cx="{x}" cy="{y}" r="5" fill="#15803d"/>',f'<text x="{x}" y="415" text-anchor="middle">{label}</text>',f'<text x="{x}" y="{y-10}" text-anchor="middle">{value:.2f}</text>']
    return ''.join(parts)+f'<polyline points="{" ".join(points)}" fill="none" stroke="#15803d" stroke-width="3"/></svg>'
def _lineage(f):
    labels=["T1 retrieval","M1 memory","T3 summary","T5 cache","T7 context","T8 effect"]
    parts=[_start("Delayed T1 to T8 explicit lineage")]
    for i,label in enumerate(labels):
        x=35+i*160;parts += [f'<rect x="{x}" y="170" width="125" height="65" rx="7" fill="{("#fee2e2" if i in (0,5) else "#dbeafe")}" stroke="#334155"/>',f'<text x="{x+62}" y="207" text-anchor="middle">{label}</text>']
        if i<len(labels)-1:parts.append(f'<path d="M{x+125} 202 H{x+160}" class="a"/>')
    return ''.join(parts)+f'<text x="35" y="280">Actual root: {f["root_untrusted_source"]}; effect executed: {str(f["effect_executed"]).lower()}</text></svg>'
def _architecture(): return _start("Selective recovery architecture")+'''<rect x="35" y="130" width="170" height="70" rx="7" fill="#fee2e2" stroke="#334155"/><text x="120" y="170" text-anchor="middle">detected unsafe node</text><path d="M205 165 H305" class="a"/><rect x="305" y="115" width="190" height="100" rx="7" fill="#dbeafe" stroke="#334155"/><text x="400" y="150" text-anchor="middle">authoritative lineage</text><text x="400" y="174" text-anchor="middle">analyze contamination</text><path d="M495 165 H595" class="a"/><rect x="595" y="115" width="170" height="100" rx="7" fill="#fef3c7" stroke="#334155"/><text x="680" y="150" text-anchor="middle">revision-bound plan</text><text x="680" y="174" text-anchor="middle">trusted apply</text><path d="M765 165 H845" class="a"/><rect x="845" y="95" width="135" height="60" fill="#ede9fe" stroke="#334155"/><text x="912" y="130" text-anchor="middle">quarantine</text><rect x="845" y="180" width="135" height="60" fill="#e0e7ff" stroke="#334155"/><text x="912" y="215" text-anchor="middle">invalidate</text><text x="400" y="285" text-anchor="middle">historical commits and audit evidence remain unchanged</text></svg>'''
def _report(doc):
    s=doc["corpus"]["summary"];f=doc["flagship"]
    return f'''# Stage 12E measured summary

Delayed attacks: {s["delayed_attack_count"]}. Root causes found: {s["root_cause_found"]}/{s["denominators"]["attacks"]}; correct origin transaction/session/source: {s["correct_origin_transaction"]}/{s["correct_origin_session"]}/{s["correct_origin_source"]} of {s["denominators"]["attacks"]}. Contamination precision: {s["contamination_precision"]:.1%}; recall: {s["contamination_recall"]:.1%}. Recovery success: {s["recovery_success"]}/{s["denominators"]["attacks"]}. Unrelated-state preservation: {s["unrelated_state_preservation"]:.1%}; post-recovery leakage: {s["post_recovery_leakage"]}. Over-quarantine: {s["over_quarantine_rate"]:.1%}; under-recovery: {s["under_recovery_rate"]:.1%}.

The flagship attributed `{f["detected_effect_id"]}` to `{f["root_untrusted_source"]}` in {f["transaction_ids"]["T1"]}, quarantined the original persistent memory, invalidated three derived values, preserved three unrelated values, and did not execute the simulated effect. These controlled explicit-lineage results are not estimates of semantic attribution in deployment.
'''
def _json(path,value): path.write_text(json.dumps(value,indent=2,sort_keys=True,default=repr))
def _csv(path,rows):
    if not rows:path.write_text("");return
    fields=list(dict.fromkeys(k for row in rows for k in row))
    with path.open("w",newline="") as h:w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows(rows)
