"""Stage 11 standard-library tables and measured-data SVG figures."""
from pathlib import Path
from .stage8_reporting import _csv,_svg

def generate_stage11_artifacts(*,interface,failures,security,benign,multi_turn,overhead,
    policy_failures,complexity,stage10_reliability,output_dir:Path):
    tables=output_dir/"tables";figures=output_dir/"figures";tables.mkdir(parents=True,exist_ok=True);figures.mkdir(parents=True,exist_ok=True)
    paths=[
      _csv(tables/"table_1_interface_reliability.csv",interface,fallback=("model","mode","attempts","raw_parse_success","normalized_parse_success","timeout_rate")),
      _csv(tables/"table_2_parse_failure_taxonomy.csv",failures,fallback=("model","mode","scenario_type","category","count","percentage")),
      _csv(tables/"table_3_compromise_policy_detection.csv",security,fallback=("model","attempts","model_compromise","policy_v2_recall")),
      _csv(tables/"table_4_policy_per_model.csv",security,fallback=("model","policy","recall","fpr")),
      _csv(tables/"table_5_persistence_leakage.csv",security,fallback=("model","policy","persistent_compromise","external_leakage")),
      _csv(tables/"table_6_hard_benign.csv",benign,fallback=("model","scenario_id","policy","reason")),
      _csv(tables/"table_7_multi_turn.csv",multi_turn,fallback=("model","scenario_id","later_detection")),
      _csv(tables/"table_8_enforcement_overhead.csv",overhead,fallback=("model","count","mean","median","overhead_fraction")),
      _csv(tables/"table_9_live_policy_failures.csv",policy_failures,fallback=("model","scenario_id","attack_family","malicious_reason")),
      _csv(tables/"table_10_complexity.csv",_complexity(complexity))]
    v2=[x for x in security if x.get("policy")=="policy_v2"]
    plots=(
      ("figure_1_raw_normalized.svg","Raw vs normalized parse success",[(f"{x['model']} raw",x.get("raw_parse_rate",0)) for x in interface]+[(f"{x['model']} normalized",x.get("normalized_parse_rate",0)) for x in interface]),
      ("figure_2_modes.svg","Parse success by generation mode",[(f"{x['model']} {x.get('mode')}",x.get("normalized_parse_rate",0)) for x in interface]),
      ("figure_3_failures.svg","Interface failure categories",[(x.get("category","none"),x.get("count",0)) for x in failures]),
      ("figure_4_compromise.svg","Model compromise",[(x.get("model","none"),x.get("model_compromise_rate") or 0) for x in v2]),
      ("figure_5_policy_recall.svg","PolicyV1 vs PolicyV2 recall",[(f"{x.get('model')} {x.get('policy')}",x.get("recall") or 0) for x in security]),
      ("figure_6_benign.svg","Benign completion and false rejection",[(f"{x.get('model')} completion",x.get("benign_completion") or 0) for x in v2]+[(f"{x.get('model')} false rejection",x.get("false_rejection") or 0) for x in v2]),
      ("figure_7_persistence.svg","Persistent compromise",[(x.get("model","none"),x.get("persistent_compromise") or 0) for x in v2]),
      ("figure_8_pipeline.svg","Compromise to detection to containment",[("compromise",v2[0].get("model_compromise_rate",0)),("detection",v2[0].get("recall") or 0),("containment",v2[0].get("containment") or 0)] if v2 else []),
      ("figure_9_multi_turn.svg","Multi-turn outcomes",[(x.get("scenario_id","none"),float(x.get("policy_v2_later_detection",False))) for x in multi_turn]),
      ("figure_10_latency.svg","Generation vs enforcement latency",[("generation",overhead[0].get("median_generation_ns",0)/1e6),("enforcement",overhead[0].get("median",0)/1e6)] if overhead else []),
      ("figure_11_overhead.svg","Transactional overhead percent",[(x.get("model","none"),x.get("overhead_percent",0)) for x in overhead]),
      ("figure_12_stage10_stage11.svg","Stage 10 vs Stage 11 interface reliability",[("Stage 10 Llama explicit",stage10_reliability),("Stage 11 Llama v2",next((x.get("normalized_parse_rate",0) for x in interface if x.get("model")=="llama3.2:3b"),0))]))
    for name,title,values in plots:paths.append(_svg(figures/name,title,values))
    return tuple(paths)
def _complexity(c):
    return [{"area":a,"metric":m,"stage10":v.get("stage10") if isinstance(v,dict) else None,"stage11":v.get("stage11") if isinstance(v,dict) else v,"growth_percent":v.get("growth_percent") if isinstance(v,dict) else None} for a,items in c.items() for m,v in (items.items() if isinstance(items,dict) else [("value",items)])]
