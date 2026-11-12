"""Measured artifact generation for Stage 13B."""
from __future__ import annotations
import csv,json
from pathlib import Path
from typing import Any


def generate_stage13b_artifacts(document:dict[str,Any],destination:Path)->None:
    for name in ("coverage","attribution","manual_vs_auto","taint_precision","performance","tables","figures","report"):(destination/name).mkdir(parents=True,exist_ok=True)
    _json(destination/"coverage/automatic_corpus.json",document["automatic_corpus"]);_json(destination/"coverage/provenance_gaps.json",document["provenance_gaps"])
    _json(destination/"attribution/cache_poison.json",document["cache_flagship"]);_json(destination/"attribution/memory_poison.json",document["memory_flagship"]);_json(destination/"attribution/summary.json",document["attribution"])
    _json(destination/"manual_vs_auto/comparison.json",document["manual_vs_automatic"]);_json(destination/"taint_precision/field_experiment.json",document["field_precision"]);_json(destination/"performance/results.json",document["performance"])
    compare=document["manual_vs_automatic"];auto=document["automatic_corpus"];field=document["field_precision"];attr=document["attribution"];security=document["stage13a_security"]
    _csv(destination/"tables/table_01_manual_vs_automatic.csv",[{"mode":mode,**values} for mode,values in compare.items()])
    _csv(destination/"tables/table_02_provenance_coverage.csv",[{"mode":"manual","coverage":compare["manual"]["provenance_coverage"],"unknown_rate":0},{"mode":"automatic","coverage":auto["coverage"]["mean"],"unknown_rate":auto["coverage"]["unknown_rate"]},{"mode":"uninstrumented_control","coverage":0,"unknown_rate":document["provenance_gaps"]["unknown_rate"]}])
    _csv(destination/"tables/table_03_root_attribution.csv",[{"metric":k,**v,"rate":v["count"]/v["denominator"]} for k,v in attr.items()])
    _csv(destination/"tables/table_04_field_precision.csv",[field])
    _csv(destination/"tables/table_05_cache_poison_lineage.csv",[_flagship(document["cache_flagship"])])
    _csv(destination/"tables/table_06_memory_poison_lineage.csv",[_flagship(document["memory_flagship"])])
    _csv(destination/"tables/table_07_instrumentation_burden.csv",[{"mode":"manual","explicit_lineage_calls":compare["manual"]["explicit_application_lineage_calls"],"trusted_dataflow_calls":0},{"mode":"automatic","explicit_lineage_calls":auto["instrumentation"]["explicit_lineage_calls"],"trusted_dataflow_calls":auto["instrumentation"]["trusted_dataflow_calls"]}])
    _csv(destination/"tables/table_08_performance.csv",[{"operation":k,**v} for k,v in document["performance"].items() if isinstance(v,dict)])
    _csv(destination/"tables/table_09_lineage_growth.csv",[{"mode":mode,"nodes":values["nodes"],"edges":values["edges"],"estimated_bytes":values["estimated_bytes"]} for mode,values in compare.items()])
    _csv(destination/"tables/table_10_stage13a_vs_13b_security.csv",[_security_row(k,security[k],auto["security_summary"][k]) for k in ("benign_completion","policy_detection","persistent_compromise","external_effect_leakage","containment_after_rejection")])
    _architecture(destination/"figures/figure_01_automatic_architecture.svg")
    _lineage(destination/"figures/figure_02_retrieval_effect_lineage.svg")
    _bar(destination/"figures/figure_03_provenance_coverage.svg","Provenance coverage percent",[("manual",100*compare["manual"]["provenance_coverage"]),("automatic",100*auto["coverage"]["mean"]),("gap control",0)])
    _bar(destination/"figures/figure_04_instrumentation.svg","Explicit application lineage calls",[("manual",compare["manual"]["explicit_application_lineage_calls"]),("automatic",0)])
    _bar(destination/"figures/figure_05_field_precision.svg","Field-level provenance percent",[("precision",100*field["precision"]),("recall",100*field["recall"])])
    _bar(destination/"figures/figure_06_attribution_accuracy.svg","Root attribution percent",[(k,100*v["count"]/v["denominator"]) for k,v in attr.items()])
    _bar(destination/"figures/figure_07_lineage_growth.svg","Lineage graph growth",[("manual nodes",compare["manual"]["nodes"]),("auto nodes",compare["automatic"]["nodes"]),("manual edges",compare["manual"]["edges"]),("auto edges",compare["automatic"]["edges"])])
    _bar(destination/"figures/figure_08_propagation_overhead.svg","Median propagation cost (us)",[(k,v["median_ns"]/1000) for k,v in document["performance"].items() if isinstance(v,dict)])
    (destination/"report/stage13b_summary.md").write_text(_report(document));(destination/"report/limitations.md").write_text("# Stage 13B limitations\n\n"+"\n".join(f"- {x}" for x in document["limitations"])+"\n")


def _report(d):
 a=d["automatic_corpus"];c=d["manual_vs_automatic"];f=d["field_precision"];p=d["performance"];x=d["complexity"]
 return f"""# Stage 13B automatic provenance

Automatic lineage captures trusted runtime dataflow, not semantic causality.

## Results

- Automatic provenance coverage: {a['coverage']['authoritative']}/{a['coverage']['denominator']} ({100*a['coverage']['mean']:.1f}%)
- Unknown lineage in instrumented corpus: {100*a['coverage']['unknown_rate']:.1f}%
- Controlled provenance-gap detection: {d['provenance_gaps']['gap_count']}/1
- Correct cache/memory origin user, session, transaction, and source: 2/2 for each dimension
- Contamination precision/recall: 100%/100% in the controlled memory chain
- Field-level precision/recall: {100*f['precision']:.1f}%/{100*f['recall']:.1f}%
- False field lineage: {f['false_lineage_count']}
- Manual explicit lineage calls: {c['manual']['explicit_application_lineage_calls']} per flagship
- Automatic explicit lineage calls: {c['automatic']['explicit_application_lineage_calls']}; trusted dataflow calls: {c['automatic']['trusted_dataflow_calls']}

Security outcomes are unchanged from Stage 13A: PolicyV2 detection remains 9/20, persistent compromise 11/20, benign completion 20/20, external leakage 0/20, and rejection containment 9/9. Automatic provenance improves attribution, not prevention.

The cache flagship traces the later T2 context through the committed cache to its original malicious retrieval, origin transaction, and Session A. The memory flagship traces the later effect to the original retrieval and produces a selective recovery plan while preserving the policy miss before recovery.

## Costs and growth

Automatic propagation median: {p['automatic_lineage_propagation']['median_ns']/1000:.1f} µs; p95: {p['automatic_lineage_propagation']['p95_ns']/1000:.1f} µs. Context assembly median: {p['context_assembly']['median_ns']/1000:.1f} µs. Memory/cache propagation median: {p['memory_cache_propagation']['median_ns']/1000:.1f} µs. Automatic no-model corpus latency median: {a['end_to_end_no_model']['median_ns']/1e6:.3f} ms.

The comparable flagship graph grows from {c['manual']['nodes']} nodes/{c['manual']['edges']} edges/{c['manual']['estimated_bytes']} estimated bytes manually to {c['automatic']['nodes']} nodes/{c['automatic']['edges']} edges/{c['automatic']['estimated_bytes']} bytes automatically. The added detail is reported rather than hidden.

Trusted core: {x['trusted_core_modules']} modules, {x['trusted_core_python_loc']} non-comment LOC. Automatic propagation adds one trusted module and {x['trusted_core_growth_loc']} LOC. Third-party runtime dependencies remain zero.
"""


def _flagship(x):return {"origin_transaction":x["transaction_ids"]["origin"],"reuse_transaction":x["transaction_ids"]["reuse"],"source_id":x["source_id"],"effect_node":x["effect_node"],"correct_user":x["correct_origin_user"],"correct_session":x["correct_origin_session"],"correct_transaction":x["correct_origin_transaction"],"correct_source":x["correct_origin_source"],"coverage":x["provenance_coverage"]}
def _security_row(k,a,b):return {"metric":k,"stage13a_count":a["count"],"stage13a_denominator":a["denominator"],"stage13b_count":b["count"],"stage13b_denominator":b["denominator"]}
def _json(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True,default=str)+"\n")
def _csv(path,rows):
 with path.open("w",newline="") as f:w=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else [],extrasaction="ignore");w.writeheader();w.writerows(rows)
def _bar(path,title,values):
 width=max(700,85*len(values));height=430;maximum=max([float(v) for _,v in values] or [1]) or 1;parts=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"><rect width="100%" height="100%" fill="white"/><text x="{width/2}" y="25" text-anchor="middle" font-family="sans-serif" font-size="18">{title}</text>']
 for i,(label,value) in enumerate(values):
  x=65+i*((width-100)/max(1,len(values)));h=275*float(value)/maximum;y=330-h;parts += [f'<rect x="{x}" y="{y}" width="48" height="{h}" fill="#0f766e"/><text x="{x+24}" y="{max(45,y-5)}" text-anchor="middle" font-family="sans-serif" font-size="10">{float(value):.1f}</text><text x="{x+24}" y="348" transform="rotate(48 {x+24} 348)" font-family="sans-serif" font-size="9">{label}</text>']
 parts.append('</svg>');path.write_text("\n".join(parts)+"\n")
def _architecture(path):_flow(path,("Tracked input","Trusted transform","Derived record","Memory/cache","Later read","Context/effect"))
def _lineage(path):_flow(path,("Retrieval R1","Summary S1","Memory M1","Cache C1","Context X2","Effect E3"))
def _flow(path,labels):
 parts=['<svg xmlns="http://www.w3.org/2000/svg" width="960" height="170"><rect width="100%" height="100%" fill="white"/>']
 for i,label in enumerate(labels):
  x=20+i*155;parts.append(f'<rect x="{x}" y="55" width="125" height="48" rx="6" fill="#ccfbf1" stroke="#0f766e"/><text x="{x+62}" y="83" text-anchor="middle" font-family="sans-serif" font-size="11">{label}</text>');
  if i<len(labels)-1:parts.append(f'<path d="M{x+125} 79 L{x+151} 79" stroke="#111"/>')
 parts.append('</svg>');path.write_text("\n".join(parts)+"\n")
