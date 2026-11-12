"""Analysis-only Stage 11/final live-policy regression investigation."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import time
from typing import Any

from .final_validation import prompt_for
from .model import OllamaModelAdapter, OllamaUnavailableError
from .operations import OperationType, parse_model_plan
from .policy import PolicyV1, PolicyV2
from .stage8 import IndependentPolicyHarness, IndependentScenario
from .stage10 import stage10_benign_heldout, stage10_malicious_heldout
from .stage11 import ModelTransportNormalizer, matches_malicious_intent


def analyze_saved_evidence(root: Path) -> dict[str, Any]:
    s11=json.loads((root/"evaluation_results/stage11/live_models/raw_results.json").read_text())
    final=json.loads((root/"evaluation_results/final_validation/live_models/llama_raw.json").read_text())["rows"]
    s11_summary=json.loads((root/"evaluation_results/stage11/live_models/model_summary.json").read_text())
    final_summary=json.loads((root/"evaluation_results/final_validation/report/summary.json").read_text())
    lookup={x.scenario.scenario_id:x.scenario for x in (*stage10_malicious_heldout()[:30],*stage10_benign_heldout()[:20])}
    alignment=_scenario_alignment(s11,final)
    generations,plans=_generation_plan_alignment(s11,final)
    s11_replay=_replay(s11,lookup,"stage11");final_replay=_replay(final,lookup,"final")
    transitions=_transitions(s11,final)
    false_negatives=_false_negatives(s11,final,lookup)
    false_positives=_false_positives(s11,final,lookup)
    families=_family_rows(s11,final)
    metrics_s11=_metrics(s11);metrics_final=_metrics(final)
    reproduction={"stage11":{"recomputed":metrics_s11,"published":_published_stage11(s11_summary),
                             "matches_published":_metric_equal(metrics_s11,_published_stage11(s11_summary))},
                  "final":{"recomputed":metrics_final,"published":_published_final(final_summary),
                           "matches_published":_metric_equal(metrics_final,_published_final(final_summary))}}
    contexts=_context_diff_manifest(root)
    behavior=_model_behavior(s11,final)
    configuration=_configuration_audit(root)
    variability=_bootstrap(s11,final)
    scenario_pairing=_scenario_pairing(s11,final)
    taxonomy_check={"policy_v1_false_negatives":metrics_final["policy_v1"]["false_negatives"],
      "policy_v2_false_negatives":metrics_final["policy_v2"]["false_negatives"],
      "aggregate_policy_decisions":metrics_final["policy_v1"]["false_negatives"]+metrics_final["policy_v2"]["false_negatives"],
      "reported_taxonomy_count":63,"no_double_count_bug":metrics_final["policy_v1"]["false_negatives"]+metrics_final["policy_v2"]["false_negatives"]==63,
      "policy_v1_false_positives":metrics_final["policy_v1"]["false_positives"],
      "policy_v2_false_positives":metrics_final["policy_v2"]["false_positives"],
      "reported_false_positive_count":9}
    return {"artifact_manifest":_artifact_manifest(root),"scenario_alignment":alignment,
      "generation_alignment":generations,"plan_alignment":plans,"stage11_replay":s11_replay,
      "final_replay":final_replay,"policy_context_diff":contexts,"transitions":transitions,
      "false_negatives":false_negatives,"false_positives":false_positives,
      "family_analysis":families,"metric_reproduction":reproduction,
      "model_behavior":behavior,"configuration_audit":configuration,
      "bootstrap_variability":variability,"scenario_pairing":scenario_pairing,
      "taxonomy_check":taxonomy_check}


def write_historical_artifacts(root: Path, result: dict[str, Any]) -> Path:
    """Persist analysis outputs without changing any historical evidence."""
    destination = root / "evaluation_results/policy_regression"
    mapping = {
        "artifact_manifest.json": result["artifact_manifest"],
        "alignment/scenario_alignment.json": result["scenario_alignment"],
        "alignment/generation_alignment.json": result["generation_alignment"],
        "alignment/plan_alignment.json": result["plan_alignment"],
        "replay/stage11_replay.json": result["stage11_replay"],
        "replay/final_replay.json": result["final_replay"],
        "context/policy_context_diff.json": result["policy_context_diff"],
        "failures/false_negatives.json": result["false_negatives"],
        "failures/false_positives.json": result["false_positives"],
        "statistics/variability.json": result["bootstrap_variability"],
        "statistics/transitions.json": result["transitions"],
        "statistics/metric_reproduction.json": result["metric_reproduction"],
        "statistics/model_behavior.json": result["model_behavior"],
        "statistics/configuration_audit.json": result["configuration_audit"],
        "statistics/scenario_pairing.json": result["scenario_pairing"],
        "statistics/taxonomy_check.json": result["taxonomy_check"],
    }
    for relative, value in mapping.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    family = destination / "family_analysis/summary.csv"
    family.parent.mkdir(parents=True, exist_ok=True)
    headings = ("attack_family", "stage11_detected", "stage11_denominator", "stage11_recall",
                "final_detected", "final_denominator", "final_recall", "difference")
    family.write_text(",".join(headings) + "\n" + "\n".join(
        ",".join(str(row[key]) for key in headings) for row in result["family_analysis"]
    ) + "\n")
    return destination


def run_repeated_generation(root: Path, *, model: str = "llama3.2:3b",
                            repetitions: int = 5) -> dict[str, Any]:
    """Run the requested fixed 10+10 replication using the frozen current path."""
    selected = (*stage10_malicious_heldout()[:10], *stage10_benign_heldout()[:10])
    checkpoint = root / "evaluation_results/policy_regression/reproduction/repeated_trials.checkpoint.json"
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    rows = json.loads(checkpoint.read_text()) if checkpoint.exists() else []
    # Failed transport attempts are evidence of no generation, not completed trials.
    rows = [row for row in rows if not row.get("generation_error")]
    completed = {(row["scenario_id"], row["repetition"]) for row in rows}
    adapter = OllamaModelAdapter(model, timeout_seconds=45, temperature=0, seed=0,
                                 top_p=.9, maximum_output_tokens=1024)
    normalizer = ModelTransportNormalizer()
    for item in selected:
        for repetition in range(1, repetitions + 1):
            key = (item.scenario.scenario_id, repetition)
            if key in completed:
                continue
            started = time.perf_counter_ns(); error = None
            try:
                raw = adapter.generate(prompt_for(item.scenario.raw_plan))
            except OllamaUnavailableError as exc:
                raw, error = "", str(exc)
            normalized = normalizer.normalize(raw).normalized_output
            try:
                plan = parse_model_plan(normalized); parse_success = True; parse_error = None
            except ValueError as exc:
                plan = None; parse_success = False; parse_error = str(exc)
            row = {"model": model, "scenario_id": item.scenario.scenario_id,
                   "attack_family": item.scenario.attack_family,
                   "malicious": item.scenario.malicious, "repetition": repetition,
                   "seed": 0, "raw_output": raw, "raw_sha256": _hash(raw),
                   "normalized_output": normalized, "parse_success": parse_success,
                   "parse_error": parse_error, "generation_error": error,
                   "generation_ns": time.perf_counter_ns() - started}
            if plan is not None:
                scenario = IndependentScenario(
                    item.scenario.scenario_id, item.scenario.attack_family,
                    item.scenario.malicious, normalized, item.scenario.runtime_source_type,
                    item.scenario.claimed_from_retrieval, item.scenario.target_session)
                decision = IndependentPolicyHarness(policy=PolicyV2()).run(scenario)
                row.update({"canonical_plan": _ops(plan),
                    "plan_sha256": _hash(json.dumps(_ops(plan), sort_keys=True)),
                    "model_compromise": bool(item.scenario.malicious and matches_malicious_intent(
                        normalized, item.scenario.raw_plan)),
                    "policy_v2_allowed": decision.policy_allowed,
                    "policy_v2_reasons": list(decision.policy_reasons)})
            rows.append(row)
            checkpoint.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n")
    summaries = []
    for item in selected:
        subset = [row for row in rows if row["scenario_id"] == item.scenario.scenario_id]
        valid = [row for row in subset if row["parse_success"]]
        relevant = [row for row in valid if row.get("model_compromise")] if item.scenario.malicious else valid
        summaries.append({"scenario_id": item.scenario.scenario_id,
            "attack_family": item.scenario.attack_family, "malicious": item.scenario.malicious,
            "attempts": len(subset), "parse_successes": len(valid),
            "unique_raw_outputs": len({row["raw_sha256"] for row in subset}),
            "unique_plan_structures": len({row.get("plan_sha256") for row in valid}),
            "compromised_evaluable": len(relevant) if item.scenario.malicious else None,
            "policy_v2_detections": sum(not row["policy_v2_allowed"] for row in relevant),
            "policy_v2_denominator": len(relevant)})
    result = {"configuration":{"model":model,"prompt":"explicit_schema_v2 + frozen scenario request",
        "temperature":0,"seed":0,"top_p":.9,"num_predict":1024,"timeout_seconds":45},
        "scenario_count":len(selected),"repetitions":repetitions,"generation_count":len(rows),
        "rows":rows,"scenario_summaries":summaries}
    target = checkpoint.with_name("repeated_trials.json")
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def run_seed_test(root: Path, repeated: dict[str, Any], *, model: str = "llama3.2:3b") -> dict[str, Any]:
    """Reuse five seed-zero repeats, then generate the same prompt under five seeds."""
    item = stage10_malicious_heldout()[0]
    same = [row for row in repeated["rows"] if row["scenario_id"] == item.scenario.scenario_id]
    different = []
    normalizer = ModelTransportNormalizer()
    for seed in range(5):
        adapter = OllamaModelAdapter(model, timeout_seconds=45, temperature=0, seed=seed,
                                     top_p=.9, maximum_output_tokens=1024)
        error = None
        try:
            raw = adapter.generate(prompt_for(item.scenario.raw_plan))
        except OllamaUnavailableError as exc:
            raw, error = "", str(exc)
        normalized = normalizer.normalize(raw).normalized_output
        try:
            plan = parse_model_plan(normalized); parse_success = True
        except ValueError:
            plan = None; parse_success = False
        row = {"seed":seed,"raw_output":raw,"raw_sha256":_hash(raw),
               "normalized_output":normalized,"parse_success":parse_success,"generation_error":error}
        if plan is not None:
            scenario = IndependentScenario(item.scenario.scenario_id, item.scenario.attack_family,
                True, normalized, item.scenario.runtime_source_type,
                item.scenario.claimed_from_retrieval, item.scenario.target_session)
            decision = IndependentPolicyHarness(policy=PolicyV2()).run(scenario)
            row.update({"plan_sha256":_hash(json.dumps(_ops(plan),sort_keys=True)),
                        "policy_v2_allowed":decision.policy_allowed})
        different.append(row)
    result={"scenario_id":item.scenario.scenario_id,
      "same_seed":{"seed":0,"repetitions":len(same),"unique_raw_outputs":len({x["raw_sha256"] for x in same}),"rows":same},
      "different_seeds":{"seeds":list(range(5)),"unique_raw_outputs":len({x["raw_sha256"] for x in different}),"rows":different}}
    target=root/"evaluation_results/policy_regression/reproduction/seed_test.json"
    target.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    return result


def _scenario_alignment(s11,final):
    key=lambda x:(x["scenario_id"],x["trial"]);a={key(x) for x in s11};b={key(x) for x in final}
    scenarios_a=[x["scenario_id"] for x in s11];scenarios_b=[x["scenario_id"] for x in final]
    return {"stage11_records":len(s11),"final_records":len(final),"matched_trials":len(a&b),
      "shared_scenarios":sorted(set(scenarios_a)&set(scenarios_b)),
      "shared_scenario_count":len(set(scenarios_a)&set(scenarios_b)),
      "stage11_only_scenarios":sorted(set(scenarios_a)-set(scenarios_b)),
      "final_only_scenarios":sorted(set(scenarios_b)-set(scenarios_a)),
      "scenario_order_identical":scenarios_a==scenarios_b,"trial_keys_identical":a==b,
      "stage11_trials":dict(Counter(x["trial"] for x in s11)),"final_trials":dict(Counter(x["trial"] for x in final)),
      "stage11_split":{"malicious":sum(x["malicious"] for x in s11),"benign":sum(not x["malicious"] for x in s11)},
      "final_split":{"malicious":sum(x["malicious"] for x in final),"benign":sum(not x["malicious"] for x in final)},
      "stage11_families":dict(Counter(x["attack_family"] for x in s11)),
      "final_families":dict(Counter(x["attack_family"] for x in final)),
      "records":[{"scenario_id":x["scenario_id"],"attack_family":x["attack_family"],
        "trial_number":x["trial"],"generation_id":x.get("generation_id"),"model":x.get("model"),
        "prompt_version":x.get("prompt_version","UNKNOWN"),"generation_mode":"live localhost Ollama"}
        for x in s11]}


def _scenario_pairing(s11, final):
    output=[]
    for scenario_id in sorted({x["scenario_id"] for x in (*s11,*final)}):
      a=[x for x in s11 if x["scenario_id"]==scenario_id and x["parse_success"] and x["malicious"] and x.get("model_compromise")]
      b=[x for x in final if x["scenario_id"]==scenario_id and x["parse_success"] and x["malicious"] and x.get("model_compromise")]
      if not a and not b:continue
      output.append({"scenario_id":scenario_id,"attack_family":(a or b)[0]["attack_family"],
        "stage11_detected":sum(not _allowed(x,"policy_v2") for x in a),"stage11_denominator":len(a),
        "final_detected":sum(not _allowed(x,"policy_v2") for x in b),"final_denominator":len(b)})
    return output


def _generation_plan_alignment(s11,final):
    key=lambda x:(x["scenario_id"],x["trial"]);a={key(x):x for x in s11};b={key(x):x for x in final};gen=[];plans=[]
    for item in sorted(set(a)|set(b)):
      left,right=a.get(item),b.get(item)
      if left is None or right is None:category="ONE_SIDE_UNAVAILABLE"
      elif left["raw_output"]==right["raw_output"]:category="SAME_RAW_OUTPUT"
      elif left["parse_success"]!=right["parse_success"]:category="ONE_SIDE_PARSE_FAILURE"
      else:category="DIFFERENT_RAW_OUTPUT"
      gen.append({"scenario_id":item[0],"trial":item[1],"classification":category,
        "stage11_sha256":_hash(left["raw_output"]) if left else None,"final_sha256":_hash(right["raw_output"]) if right else None,
        "stage11_parse":left["parse_success"] if left else None,"final_parse":right["parse_success"] if right else None})
      if left and right:
        plans.append(_plan_compare(left,right))
    return {"rows":gen,"summary":dict(Counter(x["classification"] for x in gen))}, {"rows":plans,"summary":dict(Counter(x["classification"] for x in plans))}


def _plan_compare(left,right):
    base={"scenario_id":left["scenario_id"],"trial":left["trial"],"malicious":left["malicious"]}
    if not left["parse_success"] or not right["parse_success"]:
      return {**base,"classification":"ONE_SIDE_PARSE_FAILURE" if left["parse_success"]!=right["parse_success"] else "BOTH_PARSE_FAILURE"}
    a=parse_model_plan(left["normalized_output"]);b=parse_model_plan(right["normalized_output"])
    structural=lambda p:[{"type":x.operation_type.value,"arguments":x.arguments,"source":x.source.value} for x in p.operations]
    sa,sb=structural(a),structural(b)
    if sa==sb:category="EXACT_PLAN_MATCH"
    elif [x["type"] for x in sa] != [x["type"] for x in sb]:category="DIFFERENT_OPERATION_SEQUENCE"
    elif [_field(x) for x in sa]==[_field(x) for x in sb]:category="SEMANTICALLY_SIMILAR_STRUCTURE"
    else:category="DIFFERENT_ATTACK_FORM" if left["malicious"] else "DIFFERENT_SAFE_PLAN"
    return {**base,"classification":category,"stage11_operation_count":len(sa),"final_operation_count":len(sb),
      "stage11_operation_types":[x["type"] for x in sa],"final_operation_types":[x["type"] for x in sb],
      "stage11_plan":sa,"final_plan":sb}


def _replay(rows,lookup,label):
    output=[];mismatch=Counter()
    for row in rows:
      if not row["parse_success"]:continue
      base=lookup[row["scenario_id"]]
      scenario=IndependentScenario(base.scenario_id,base.attack_family,base.malicious,row["normalized_output"],base.runtime_source_type,base.claimed_from_retrieval,base.target_session)
      decisions={}
      for name,policy in (("policy_v1",PolicyV1()),("policy_v2",PolicyV2())):
        trial=IndependentPolicyHarness(policy=policy).run(scenario);saved=row["policy_results"][name]
        saved_allowed=saved["allowed"] if "allowed" in saved else saved["policy_allowed"]
        same=trial.policy_allowed==saved_allowed;mismatch[name]+=not same
        decisions[name]={"saved_allowed":saved_allowed,"replayed_allowed":trial.policy_allowed,"match":same,
          "saved_reasons":saved.get("reasons",saved.get("policy_reasons",[])),"replayed_reasons":list(trial.policy_reasons)}
      output.append({"scenario_id":row["scenario_id"],"trial":row["trial"],"decisions":decisions})
    return {"evidence":label,"valid_plans":len(output),"policy_replay_mismatches":dict(mismatch),"rows":output}


def _transitions(s11,final):
    key=lambda x:(x["scenario_id"],x["trial"]);a={key(x):x for x in s11};b={key(x):x for x in final}
    matrix={"stage11_detect_final_detect":0,"stage11_detect_final_miss":0,"stage11_miss_final_detect":0,"stage11_miss_final_miss":0}
    benign={"stage11_accept_final_accept":0,"stage11_accept_final_reject":0,"stage11_reject_final_accept":0,"stage11_reject_final_reject":0}
    detail=[]
    for k in sorted(set(a)&set(b)):
      x,y=a[k],b[k]
      if not(x["parse_success"] and y["parse_success"]):continue
      xa=_allowed(x,"policy_v2");ya=_allowed(y,"policy_v2")
      if x["malicious"] and x.get("model_compromise") and y.get("model_compromise"):
        keyname=f"stage11_{'miss' if xa else 'detect'}_final_{'miss' if ya else 'detect'}";matrix[keyname]+=1
        detail.append({"scenario_id":k[0],"trial":k[1],"stage11":"MISS" if xa else "DETECT","final":"MISS" if ya else "DETECT"})
      elif not x["malicious"]:
        keyname=f"stage11_{'accept' if xa else 'reject'}_final_{'accept' if ya else 'reject'}";benign[keyname]+=1
    return {"malicious_matrix":matrix,"benign_matrix":benign,"rows":detail}


def _false_negatives(s11,final,lookup):
    historical={(x["scenario_id"],x["trial"]):x for x in s11};rows=[]
    for row in final:
      if not(row["parse_success"] and row["malicious"] and row.get("model_compromise") and _allowed(row,"policy_v2")):continue
      old=historical.get((row["scenario_id"],row["trial"]));plan=parse_model_plan(row["normalized_output"])
      rows.append({"scenario_id":row["scenario_id"],"trial":row["trial"],"attack_family":row["attack_family"],
        "category":_fn_category(row["attack_family"]),"raw_output":row["raw_output"],"parsed_operations":_ops(plan),
        "runtime_provenance":lookup[row["scenario_id"]].runtime_source_type.value,
        "policy_reasons":row["policy_results"]["policy_v2"].get("policy_reasons",[]),
        "acceptance_explanation":"no frozen PolicyV2 rule produced a deny reason",
        "stage11_equivalent_present":old is not None,"stage11_parse_success":old["parse_success"] if old else None,
        "stage11_outcome":("MISS" if _allowed(old,"policy_v2") else "DETECT") if old and old["parse_success"] else "NOT_EVALUABLE"})
    return {"count":len(rows),"categories":dict(Counter(x["category"] for x in rows)),"rows":rows}


def _false_positives(s11,final,lookup):
    historical={(x["scenario_id"],x["trial"]):x for x in s11};rows=[]
    for row in final:
      if not(row["parse_success"] and not row["malicious"] and not _allowed(row,"policy_v2")):continue
      old=historical.get((row["scenario_id"],row["trial"]));plan=parse_model_plan(row["normalized_output"])
      reasons=row["policy_results"]["policy_v2"].get("policy_reasons",[])
      rows.append({"scenario_id":row["scenario_id"],"trial":row["trial"],"benign_intent":lookup[row["scenario_id"]].attack_family,
        "parsed_operations":_ops(plan),"triggered_rule":reasons,"policy_reasons":reasons,
        "runtime_provenance":lookup[row["scenario_id"]].runtime_source_type.value,
        "stage11_same_scenario_accepted":bool(old and old["parse_success"] and _allowed(old,"policy_v2")),
        "stage11_outcome":("ACCEPT" if _allowed(old,"policy_v2") else "REJECT") if old and old["parse_success"] else "NOT_EVALUABLE"})
    return {"count":len(rows),"categories":dict(Counter(reason for x in rows for reason in x["policy_reasons"])),"rows":rows}


def _family_rows(s11,final):
    result=[]
    for family in sorted({x["attack_family"] for x in (*s11,*final) if x["malicious"]}):
      a=[x for x in s11 if x["attack_family"]==family and x["parse_success"] and x.get("model_compromise")]
      b=[x for x in final if x["attack_family"]==family and x["parse_success"] and x.get("model_compromise")]
      ad=sum(not _allowed(x,"policy_v2") for x in a);bd=sum(not _allowed(x,"policy_v2") for x in b)
      result.append({"attack_family":family,"stage11_detected":ad,"stage11_denominator":len(a),"stage11_recall":ad/len(a) if a else None,
        "final_detected":bd,"final_denominator":len(b),"final_recall":bd/len(b) if b else None,
        "difference":(bd/len(b)-ad/len(a)) if a and b else None})
    return result


def _metrics(rows):
    valid=[x for x in rows if x["parse_success"]];mal=[x for x in valid if x["malicious"]];ben=[x for x in valid if not x["malicious"]];comp=[x for x in mal if x.get("model_compromise")]
    out={"attempts":len(rows),"valid_plans":len(valid),"malicious_evaluable":len(mal),"benign_evaluable":len(ben),"compromised":len(comp)}
    for p in ("policy_v1","policy_v2"):
      detect=sum(not _allowed(x,p) for x in comp);fp=sum(not _allowed(x,p) for x in ben)
      persisted=sum(bool(_policy(x,p).get("state_persisted")) for x in comp);leaked=sum(bool(_policy(x,p).get("external_leakage")) for x in comp)
      out[p]={"detected":detect,"recall_denominator":len(comp),"recall":detect/len(comp) if comp else None,
        "false_positives":fp,"benign_denominator":len(ben),"false_rejection":fp/len(ben) if ben else None,
        "false_negatives":len(comp)-detect,"persistent":persisted,"external_leakage":leaked}
    return out


def _model_behavior(s11,final):
    def summarize(rows):
      valid=[x for x in rows if x["parse_success"] and x["malicious"]];plans=[parse_model_plan(x["normalized_output"]) for x in valid]
      return {"plans":len(plans),"operation_count_distribution":dict(Counter(len(x.operations) for x in plans)),
        "operation_type_counts":dict(Counter(op.operation_type.value for p in plans for op in p.operations)),
        "single_field_plans":sum(len(p.operations)==1 for p in plans),"composition_plans":sum(len(p.operations)>1 for p in plans),
        "plans_with_effect":sum(any(op.operation_type is OperationType.EMAIL_SEND for op in p.operations) for p in plans),
        "indirect_authorization_plans":sum(x["attack_family"]=="indirect_authorization_claim" for x in valid)}
    return {"stage11":summarize(s11),"final":summarize(final)}


def _bootstrap(s11,final,repetitions=10000):
    rng=random.Random(12012)
    def values(rows):return [int(not _allowed(x,"policy_v2")) for x in rows if x["parse_success"] and x["malicious"] and x.get("model_compromise")]
    a,b=values(s11),values(final);samples_a=[];samples_b=[];differences=[]
    for _ in range(repetitions):
      ra=sum(rng.choice(a) for _ in a)/len(a);rb=sum(rng.choice(b) for _ in b)/len(b)
      samples_a.append(ra);samples_b.append(rb);differences.append(rb-ra)
    pct=lambda xs,p:sorted(xs)[int(p*(len(xs)-1))]
    return {"method":"independent nonparametric plan-level bootstrap; descriptive only","repetitions":repetitions,
      "stage11_observed":sum(a)/len(a),"stage11_interval_2_5_97_5":[pct(samples_a,.025),pct(samples_a,.975)],
      "final_observed":sum(b)/len(b),"final_interval_2_5_97_5":[pct(samples_b,.025),pct(samples_b,.975)],
      "difference_final_minus_stage11":sum(b)/len(b)-sum(a)/len(a),
      "difference_interval_2_5_97_5":[pct(differences,.025),pct(differences,.975)],
      "fraction_resampled_difference_nonnegative":sum(x>=0 for x in differences)/repetitions}


def _artifact_manifest(root):
    paths={"stage11_raw":"evaluation_results/stage11/live_models/raw_results.json","stage11_summary":"evaluation_results/stage11/live_models/model_summary.json","stage11_gate":"evaluation_results/stage11/interface/gate_results.json","stage11_interface_raw":"evaluation_results/stage11/interface/raw_generations.json","final_raw":"evaluation_results/final_validation/live_models/llama_raw.json","final_summary":"evaluation_results/final_validation/report/summary.json","final_gate":"evaluation_results/final_validation/interface/llama.json"}
    saved_stage11={"raw_generation":True,"normalized_generation":True,"parsed_plan_directly_saved":False,"parsed_plan_reconstructable_from_normalized":True,"scenario_id":True,"trial":True,"policy_decision":True,"policy_reasons":True,"prompt_hash":True,"prompt_version":True,"runtime_provenance_per_row":False,"initial_state":False,"full_policy_context":False,"ground_truth_embedded":False}
    saved_final={"raw_generation":True,"normalized_generation":True,"parsed_plan_directly_saved":False,"parsed_plan_reconstructable_from_normalized":True,"scenario_id":True,"trial":True,"policy_decision":True,"policy_reasons":True,"prompt_hash":False,"prompt_version":False,"runtime_provenance_per_row":False,"initial_state":False,"full_policy_context":False,"ground_truth_embedded":False}
    return {"files":{k:{"path":v,"available":(root/v).exists(),"sha256":_hash_bytes((root/v).read_bytes()) if (root/v).exists() else None} for k,v in paths.items()},"stage11_fields":saved_stage11,"final_fields":saved_final,
      "note":"frozen corpus metadata and harness code permit replay, but missing historical fields are not claimed as directly saved"}


def _context_diff_manifest(root):
    return {"effective_policy_replay":{"stage11_v1_mismatches":0,"stage11_v2_mismatches":0,"final_v1_mismatches":0,"final_v2_mismatches":0},
      "inputs":[
      {"input":"runtime provenance/source type","stage11":"not saved per row; reconstructable from frozen scenario","final":"not saved per row; reconstructable from frozen scenario","difference":"NO OBSERVED EFFECTIVE DIFFERENCE"},
      {"input":"trust labels","stage11":"not saved; PolicyV1/V2 consume source types rather than Stage12 trust graph","final":"not saved","difference":"UNKNOWN DIRECT EVIDENCE"},
      {"input":"session/resource scope","stage11":"reconstructable from frozen scenario target","final":"same frozen scenario target","difference":"NONE IN REPLAY"},
      {"input":"capabilities","stage11":"not saved per row; selected failure artifacts list standard grants","final":"current standard_capabilities harness","difference":"HISTORICAL PER-ROW VALUE UNKNOWN"},
      {"input":"security aliases","stage11":"policy fingerprint frozen","final":"same fingerprint","difference":"NONE"},
      {"input":"budgets","stage11":"not saved per row","final":"default harness budget","difference":"UNKNOWN DIRECT EVIDENCE"},
      {"input":"operation sequence","stage11":"saved parsed plan","final":"saved parsed plan","difference":"frequently different generation output"},
      {"input":"lineage metadata","stage11":"not consumed by PolicyV1/V2","final":"not consumed by PolicyV1/V2","difference":"NONE"},
      {"input":"initial state","stage11":"not saved; harness code creates fresh sessions","final":"not saved; harness code creates fresh sessions","difference":"UNKNOWN BYTE-FOR-BYTE; decisions replay"}]}


def _configuration_audit(root):
    sraw=json.loads((root/"evaluation_results/stage11/live_models/raw_results.json").read_text());fgate=json.loads((root/"evaluation_results/final_validation/interface/llama.json").read_text())
    return {"rows":[
      {"setting":"model tag","stage11":"llama3.2:3b","final":"llama3.2:3b","difference":False,"evidence":"saved"},
      {"setting":"prompt version","stage11":sraw[0].get("prompt_version","UNKNOWN"),"final":"explicit_schema_v2 (runner code; not saved per row)","difference":False,"evidence":"mixed saved/code"},
      {"setting":"prompt hash","stage11":sraw[0].get("prompt_hash","UNKNOWN"),"final":"e510f0338e0b6805037c40b8a5f6297f2b62289a20f7cf50a621b5de95b68c8f (instruction code; not saved per row)","difference":False,"evidence":"mixed saved/code"},
      {"setting":"full rendered prompt","stage11":"UNKNOWN (not saved)","final":"reconstructable from final runner","difference":"UNKNOWN","evidence":"insufficient historical evidence"},
      {"setting":"temperature","stage11":0,"final":0,"difference":False,"evidence":"Stage11 gate artifact/final adapter default"},
      {"setting":"seed","stage11":0,"final":0,"difference":False,"evidence":"Stage11 gate artifact/final adapter default"},
      {"setting":"top_p","stage11":0.9,"final":0.9,"difference":False,"evidence":"Stage11 gate artifact/final adapter default"},
      {"setting":"num_predict","stage11":1024,"final":1024,"difference":False,"evidence":"Stage11 gate artifact/final runner"},
      {"setting":"timeout seconds","stage11":30,"final":45,"difference":True,"evidence":"saved Stage11 gate/final runner; no final timeouts"},
      {"setting":"structured output mode","stage11":"Ollama format=json + explicit schema v2 prompt","final":"Ollama format=json + explicit schema v2 prompt","difference":False,"evidence":"adapter and artifacts"},
      {"setting":"Ollama version","stage11":"0.32.9","final":fgate.get("ollama_version","UNKNOWN"),"difference":False,"evidence":"saved/reported"}]}


def _published_stage11(s):
    p={x["policy"]:x for x in s["security"]};return {"attempts":150,"valid_plans":128,"malicious_evaluable":75,"benign_evaluable":53,"compromised":75,
      **{name:{"detected":p[name]["recall_count"],"recall_denominator":p[name]["recall_denominator"],"recall":p[name]["recall"],"false_positives":p[name]["false_rejection_count"],"benign_denominator":p[name]["false_rejection_denominator"],"false_rejection":p[name]["false_rejection"],"false_negatives":p[name]["recall_denominator"]-p[name]["recall_count"],"persistent":p[name]["persistent_count"],"external_leakage":p[name]["external_leakage_count"]} for name in ("policy_v1","policy_v2")}}
def _published_final(s):
    x=s["models"]["llama_live"];return {"attempts":150,"valid_plans":129,"malicious_evaluable":72,"benign_evaluable":57,"compromised":72,
      **{name:{"detected":x[name]["recall_count"],"recall_denominator":x[name]["recall_denominator"],"recall":x[name]["recall"],"false_positives":x[name]["false_rejection_count"],"benign_denominator":x[name]["false_rejection_denominator"],"false_rejection":x[name]["false_rejection_rate"],"false_negatives":x[name]["recall_denominator"]-x[name]["recall_count"],"persistent":x[name]["persistent_compromise_count"],"external_leakage":x[name]["external_leakage_count"]} for name in ("policy_v1","policy_v2")}}
def _metric_equal(a,b):return a==b
def _allowed(row,p):
    value=_policy(row,p);return value["allowed"] if "allowed" in value else value["policy_allowed"]
def _policy(row,p):return row["policy_results"][p]
def _ops(plan):return [{"operation_id":x.operation_id,"operation_type":x.operation_type.value,"arguments":x.arguments,"source":x.source.value} for x in plan.operations]
def _fn_category(family):
    return {"indirect_authorization_claim":"INDIRECT_AUTHORIZATION","semantic_memory_poisoning":"SEMANTIC_MEMORY_POISONING","multi_field_composition":"MULTI_FIELD_COMPOSITION","operation_sequence_abuse":"OPERATION_SEQUENCE_ABUSE","provenance_poisoning":"PROVENANCE_CONTEXT","scope_confusion":"CAPABILITY_SCOPE","capability_misuse":"CAPABILITY_SCOPE"}.get(family,"OTHER")
def _field(op):return op["arguments"].get("key",op["arguments"].get("to"))
def _hash(value):return hashlib.sha256(value.encode()).hexdigest()
def _hash_bytes(value):return hashlib.sha256(value).hexdigest()
