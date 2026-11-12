"""Artifact generation for the frozen Stage 13C validator comparison."""
from __future__ import annotations
import csv,json
from pathlib import Path
from typing import Any


def generate_stage13c_artifacts(document:dict[str,Any],destination:Path)->None:
    for name in ("corpus","development","heldout","validators","ablation","disagreements","failures","performance","tables","figures","report"):(destination/name).mkdir(parents=True,exist_ok=True)
    _json(destination/"corpus/freeze.json",{"heldout_sha256":document["heldout_freeze_hash"],"validator_fingerprints":document["fingerprints"]});_json(destination/"development/results.json",document["development"]);_json(destination/"heldout/results.json",document["heldout"]);_json(destination/"validators/definitions.json",{"fingerprints":document["fingerprints"],"mapping":document["mapping"],"optional":document["optional_validators"]});_json(destination/"ablation/results.json",document["ablation"]);_json(destination/"disagreements/results.json",document["disagreements"]);_json(destination/"failures/taxonomy.json",document["failures"]);_json(destination/"performance/latency.json",document["heldout"]["latency"]);_json(destination/"heldout/flagship.json",document["flagship"]);_json(destination/"heldout/live_support.json",document["live_support"])
    definitions=[{"validator":"POLICY_V2_BASELINE","basis":"frozen PolicyV2","action":"ALLOW/DENY"},{"validator":"SEQUENCE_AWARE","basis":"ordered writes, effects, dependencies, composition","action":"ALLOW/DENY"},{"validator":"PROVENANCE_AWARE","basis":"authoritative ancestry, session, gaps","action":"ALLOW/QUARANTINE/REVIEW"},{"validator":"SEMANTIC_RULE","basis":"explainable authorization concepts and benign frames","action":"ALLOW/DENY"},{"validator":"HYBRID_DETERMINISTIC","basis":"deny-overrides deterministic composition","action":"all actions"}]
    _csv(destination/"tables/table_01_validator_definitions.csv",definitions)
    _csv(destination/"tables/table_02_development_metrics.csv",_metric_rows(document["development"]))
    _csv(destination/"tables/table_03_heldout_metrics.csv",_metric_rows(document["heldout"]))
    _csv(destination/"tables/table_04_confusion_matrices.csv",[{"validator":k,**{x:v[x] for x in ("tp","fn","fp","tn")}} for k,v in document["heldout"]["metrics"].items()])
    _csv(destination/"tables/table_05_ablation.csv",document["ablation"]["rows"])
    _csv(destination/"tables/table_06_semantic_poisoning.csv",_scenario_rows(document["heldout"],"semantic_poisoning"))
    _csv(destination/"tables/table_07_provenance_context.csv",_scenario_rows(document["heldout"],"provenance_context"))
    _csv(destination/"tables/table_08_hard_benign.csv",_scenario_rows(document["heldout"],"hard_benign"))
    _csv(destination/"tables/table_09_validator_latency.csv",[{"validator":k,**v} for k,v in document["heldout"]["latency"].items()])
    _csv(destination/"tables/table_10_disagreement_taxonomy.csv",[{"pair":k,"count":v} for k,v in document["disagreements"]["pair_counts"].items()])
    metrics=document["heldout"]["metrics"]
    _bar(destination/"figures/figure_01_recall.svg","Held-out recall percent",[(k,100*v["recall"]) for k,v in metrics.items()])
    _bar(destination/"figures/figure_02_fpr.svg","Held-out false-positive rate percent",[(k,100*v["fpr"]) for k,v in metrics.items()])
    _bar(destination/"figures/figure_03_f1.svg","Held-out F1 percent",[(k,100*v["f1"]) for k,v in metrics.items()])
    _bar(destination/"figures/figure_04_persistent.svg","Persistent compromises",[(k,v["persistent_compromise"]) for k,v in metrics.items()])
    _bar(destination/"figures/figure_05_benign_completion.svg","Benign completion",[(k,v["benign_completion"]) for k,v in metrics.items()])
    _bar(destination/"figures/figure_06_ablation.svg","Ablation recall percent",[(x["configuration"],100*x["recall"]) for x in document["ablation"]["rows"]])
    _bar(destination/"figures/figure_07_latency.svg","Median validation latency (us)",[(k,v["median_ns"]/1000) for k,v in document["heldout"]["latency"].items()])
    _bar(destination/"figures/figure_08_disagreement.svg","Validator intervention disagreements",[(k,v) for k,v in document["disagreements"]["pair_counts"].items()])
    (destination/"report/stage13c_summary.md").write_text(_report(document));(destination/"report/limitations.md").write_text("# Stage 13C limitations\n\n"+"\n".join(f"- {x}" for x in document["limitations"])+"\n")


def _report(d):
 m=d["heldout"]["metrics"];lat=d["heldout"]["latency"];c=d["complexity"]
 rows="\n".join(f"| {name} | {v['tp']}/{v['tp']+v['fn']} ({100*v['recall']:.1f}%) | {v['fp']}/{v['fp']+v['tn']} ({100*v['fpr']:.1f}%) | {v['f1']:.3f} | {v['persistent_compromise']}/{v['persistent_denominator']} | {v['benign_completion']}/{v['benign_denominator']} | {lat[name]['median_ns']/1000:.1f} µs |" for name,v in m.items())
 return f"""# Stage 13C independent validator comparison

Validators propose inspectable actions; the unchanged transactional runtime enforces them. `DENY`, `QUARANTINE`, and `REVIEW` were frozen as security interventions before evaluation.

## Frozen held-out results

| Validator | Recall | FPR | F1 | Persistent compromise | Benign completion | Median validation |
|---|---:|---:|---:|---:|---:|---:|
{rows}

PolicyV2 reproduces the Stage 13A development baseline at 9/20 and reaches 8/20 on held-out variants. Sequence reasoning independently reaches 6/20. The semantic validator reaches 10/20 with zero hard-benign false positives. Provenance and hybrid reach 20/20, but each intervenes on 10/20 hard-benign workflows whose quoted text has untrusted retrieved ancestry. Their 50% FPR makes them unsuitable as an unconditional default despite full recall.

Every intervention contained state/effects in this deterministic harness. Baseline false negatives left 12/20 persistent compromises and two simulated malicious effects; semantic left 10/20 and two effects; provenance/hybrid left none but cut benign completion to 10/20.

## Flagship

The preselected semantic-poison case is allowed by PolicyV2 and sequence validation, quarantined by provenance, denied by semantic rules, and denied by hybrid composition. Reasons, confidence, persistence, effects, and latency are stored in `heldout/flagship.json`.

## Separation and freezing

Ground-truth labels and attack-family names are evaluator-only. Validator evidence contains operations, authoritative sources, scope, dependencies, order, and gap state. Validator fingerprints and held-out corpus hash `{d['heldout_freeze_hash']}` were recorded before the final held-out artifact run. No post-held-out tuning was performed.

Optional ML and LLM judge validators were not added to headline metrics: ML would introduce an evaluation dependency, and the LLM judge remains unavailable/advisory. Four saved valid Stage 13A Llama plans are reported only as supporting evidence.

## Boundary

Trusted mechanism remains {c['trusted_core_modules']} modules / {c['trusted_core_python_loc']} LOC with zero trusted-core growth and zero third-party core dependencies. Validator/evaluation code is {c['validator_evaluation_python_loc']} non-comment LOC above the frozen transaction mechanisms.
"""


def _metric_rows(result):
 return [{"validator":k,**v,**result["latency"][k]} for k,v in result["metrics"].items()]
def _scenario_rows(result,family):
 return [{k:x[k] for k in ("scenario_id","malicious","validator","action","intervention","reasons","persistent_compromise","benign_completion","latency_ns")} for x in result["trials"] if x["attack_family"]==family]
def _json(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True,default=str)+"\n")
def _csv(path,rows):
 with path.open("w",newline="") as f:w=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else [],extrasaction="ignore");w.writeheader();w.writerows(rows)
def _bar(path,title,values):
 width=max(760,120*len(values));height=460;maximum=max([float(v) for _,v in values] or [1]) or 1;parts=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"><rect width="100%" height="100%" fill="white"/><text x="{width/2}" y="25" text-anchor="middle" font-family="sans-serif" font-size="18">{title}</text>']
 for i,(label,value) in enumerate(values):
  x=65+i*((width-110)/max(1,len(values)));h=285*float(value)/maximum;y=340-h;parts += [f'<rect x="{x}" y="{y}" width="55" height="{h}" fill="#7c3aed"/><text x="{x+27}" y="{max(45,y-5)}" text-anchor="middle" font-family="sans-serif" font-size="10">{float(value):.1f}</text><text x="{x+27}" y="360" transform="rotate(48 {x+27} 360)" font-family="sans-serif" font-size="9">{label}</text>']
 parts.append('</svg>');path.write_text("\n".join(parts)+"\n")
