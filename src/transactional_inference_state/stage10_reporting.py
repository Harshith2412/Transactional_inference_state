"""Stage 10 artifact generation using only the standard library."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from .stage8_reporting import _csv, _svg

def generate_stage10_artifacts(*, deterministic, stage9_metrics:dict[str,Any],
    reliability:list[dict[str,Any]], security:list[dict[str,Any]],
    failures:list[dict[str,Any]], multi_turn:list[dict[str,Any]],
    latency:list[dict[str,Any]], live_false_negatives:list[dict[str,Any]],
    complexity:dict[str,Any], output_dir:Path)->tuple[Path,...]:
    tables=output_dir/"tables"; figures=output_dir/"figures"; tables.mkdir(parents=True,exist_ok=True); figures.mkdir(parents=True,exist_ok=True)
    rows=[_det_row(x) for x in deterministic]; v2=next(x for x in rows if x["policy"]=="policy_v2")
    paths=[
      _csv(tables/"table_1_new_heldout.csv",rows),
      _csv(tables/"table_2_stage9_vs_stage10.csv",[
        {"metric":k,"stage9":stage9_metrics.get(k),"stage10":v2.get(k)}
        for k in ("recall","fpr","f1","persistent_compromise","benign_completion")]),
      _csv(tables/"table_3_structured_reliability.csv",reliability,fallback=("model","mode","total","valid","parse_success")),
      _csv(tables/"table_4_model_security.csv",security,fallback=("model","mode","policy","recall")),
      _csv(tables/"table_5_live_policy_comparison.csv",security,fallback=("model","mode","policy","recall")),
      _csv(tables/"table_6_parse_failures.csv",failures,fallback=("model","mode","category","count")),
      _csv(tables/"table_7_multi_turn_live.csv",multi_turn,fallback=("model","seed_persisted","later_detection")),
      _csv(tables/"table_8_live_latency.csv",latency,fallback=("model","mode","count","mean")),
      _csv(tables/"table_9_live_false_negatives.csv",live_false_negatives,fallback=("model","scenario_id","attack_family","why_accepted")),
      _csv(tables/"table_10_complexity.csv",_complexity_rows(complexity)),]
    rel_values=[(f"{x.get('model')} {x.get('mode')}",float(x.get('parse_success',0))) for x in reliability]
    sec_v2=[x for x in security if x.get("policy")=="policy_v2"]
    plots=(
      ("figure_1_generalization.svg","Stage 9 vs Stage 10 recall",[("Stage 9",stage9_metrics.get("recall",0)),("Stage 10",v2["recall"])]),
      ("figure_2_policy_tradeoff.svg","Held-out recall and FPR",[(f"{x['policy']} recall",x["recall"]) for x in rows]+[(f"{x['policy']} FPR",x["fpr"]) for x in rows]),
      ("figure_3_parse_success.svg","Parse success by model/mode",rel_values),
      ("figure_4_benign_completion.svg","Benign completion",[(f"{x.get('model')} {x.get('mode')}",float(x.get('benign_completion',0) or 0)) for x in security]),
      ("figure_5_compromise_detection.svg","Compromise vs PolicyV2 detection",[(f"{x.get('model')} compromise",float(x.get('model_compromise',0) or 0)) for x in sec_v2]+[(f"{x.get('model')} detection",float(x.get('recall',0) or 0)) for x in sec_v2]),
      ("figure_6_persistent_compromise.svg","Persistent compromise by model",[(f"{x.get('model')} {x.get('mode')}",float(x.get('persistent_compromise',0) or 0)) for x in sec_v2]),
      ("figure_7_attack_family_recall.svg","Live attack-family recall",[(x.get("attack_family","unavailable"),float(x.get("recall",0) or 0)) for x in security if "attack_family" in x]),
      ("figure_8_latency.svg","Live latency breakdown",[(f"{x.get('model')} {x.get('mode')}",float(x.get('mean',0) or 0)/1e6) for x in latency]),
      ("figure_9_overhead.svg","Transactional overhead percent",[(f"{x.get('model')} {x.get('mode')}",float(x.get('overhead_percent',0) or 0)) for x in latency]),
      ("figure_10_parse_taxonomy.svg","Parse failure taxonomy",[(x.get("category","none"),float(x.get("count",0))) for x in failures]),
      ("figure_11_multi_turn.svg","Multi-turn live outcomes",[(x.get("model","none"),float(x.get("later_detection",0))) for x in multi_turn]),
      ("figure_12_deterministic_live.svg","Deterministic vs live recall",[("deterministic V2",v2["recall"])]+[(f"live {x.get('model')}",float(x.get('recall',0) or 0)) for x in sec_v2]))
    for name,title,values in plots: paths.append(_svg(figures/name,title,values))
    return tuple(paths)

def _det_row(x):
    c=x.confusion;p=x.pipeline
    return {"policy":x.policy,"tp":c.tp,"fn":c.fn,"fp":c.fp,"tn":c.tn,"precision":c.precision,"recall":c.recall,"f1":c.f1,"fpr":c.false_positive_rate,"fnr":c.false_negative_rate,"specificity":c.specificity,"persistent_compromise":p.persistent_compromise_rate,"external_leakage":p.external_leakage_rate,"benign_completion":p.benign_completion_rate,"containment":p.containment_given_rejection}
def _complexity_rows(c):
    return [{"area":area,"metric":metric,"value":value}
            for area, values in c.items() for metric, value in values.items()
            if not isinstance(value,(list,dict))]
