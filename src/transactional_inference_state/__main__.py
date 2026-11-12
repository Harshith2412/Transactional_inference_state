"""Dependency-light command line entry point for Stage 7 evaluation."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import time

from .evaluation import EvaluationHarness, EvaluationMode
from .reporting import (
    export_snapshot_matrix, export_trial_records, generate_plots,
    generate_tables, structured_output_summary, write_research_report,
)
from .stage7 import (
    LiveEvaluationConfiguration, ModelConfiguration, SnapshotMatrixConfiguration,
    expanded_benign_corpus, expanded_malicious_corpus, paired_comparisons,
    reproducibility_metadata, run_live_model_matrix, run_snapshot_matrix,
    snapshot_crossover_analysis,
)


def main() -> None:
    parser = argparse.ArgumentParser(prog="transactional_inference_state")
    subcommands = parser.add_subparsers(dest="area", required=True)
    evaluate = subcommands.add_parser("evaluate")
    evaluate_sub = evaluate.add_subparsers(dest="command", required=True)
    evaluate_sub.add_parser("deterministic")
    evaluate_sub.add_parser("corpus")
    evaluate_sub.add_parser("stage8")
    evaluate_sub.add_parser("stage9")
    evaluate_sub.add_parser("stage10")
    evaluate_sub.add_parser("stage11")
    models = evaluate_sub.add_parser("models")
    models.add_argument("--models", nargs="+", required=True)
    models.add_argument("--trials", type=int, default=5)
    models.add_argument("--malicious-limit", type=int, default=20)
    models.add_argument("--benign-limit", type=int, default=20)
    structured = evaluate_sub.add_parser("structured-output")
    structured.add_argument("--models", nargs="+", required=True)
    structured.add_argument("--trials", type=int, default=5)

    benchmark = subcommands.add_parser("benchmark")
    benchmark_sub = benchmark.add_subparsers(dest="command", required=True)
    matrix = benchmark_sub.add_parser("snapshot-matrix")
    matrix.add_argument("--iterations", type=int, default=7)
    matrix.add_argument("--sizes", nargs="+", default=None)

    report = subcommands.add_parser("report")
    report_sub = report.add_subparsers(dest="command", required=True)
    report_sub.add_parser("plots")
    args = parser.parse_args()
    root = Path("evaluation_results")

    if args.area == "evaluate" and args.command == "stage11":
        from .stage11_reporting import generate_stage11_artifacts
        target=root/"stage11";summary_path=target/"live_models"/"model_summary.json"
        if not summary_path.exists():
            raise SystemExit("Stage 11 live artifacts are absent; run the reliability gate first")
        summary=json.loads(summary_path.read_text())
        artifacts=generate_stage11_artifacts(interface=summary["interface"],
            failures=summary["parse_failures"],security=summary["security"],
            benign=summary["benign_failures"],multi_turn=summary["multi_turn"],
            overhead=summary["performance"],policy_failures=summary["policy_failures"],
            complexity=summary["complexity"],stage10_reliability=summary["stage10_live_parse_rate"],
            output_dir=target)
        (target/"report"/"stage11_summary.md").write_text("# Stage 11 summary\n\nSee `../live_models/model_summary.json` and the generated tables.\n")
        (target/"report"/"limitations.md").write_text("# Limitations\n\nOnly Llama qualified; Qwen remained interface-unreliable. The live corpus is local and handcrafted, and transport normalization rescued no plans.\n")
        print(json.dumps({"summary":str(summary_path),"artifacts":len(artifacts)},indent=2));return

    if args.area == "evaluate" and args.command == "stage10":
        from .stage10 import (complexity_report, frozen_live_subset,
            run_deterministic_validation, serializable, stage10_benign_heldout,
            stage10_malicious_heldout)
        from .stage10_reporting import generate_stage10_artifacts
        target=root/"stage10"
        for name in ("corpus","deterministic","live_models","structured_output",
                     "multi_turn","performance","complexity","report"):
            (target/name).mkdir(parents=True,exist_ok=True)
        malicious,benign=stage10_malicious_heldout(),stage10_benign_heldout()
        (target/"corpus"/"malicious_heldout.json").write_text(json.dumps([serializable(x) for x in malicious],indent=2,sort_keys=True))
        (target/"corpus"/"benign_heldout.json").write_text(json.dumps([serializable(x) for x in benign],indent=2,sort_keys=True))
        (target/"corpus"/"live_subset_manifest.json").write_text(json.dumps({"frozen":True,"scenario_ids":frozen_live_subset(),"selection":"first 30 malicious and first 20 benign in corpus order"},indent=2))
        deterministic=run_deterministic_validation()
        (target/"deterministic"/"raw_results.json").write_text(json.dumps([serializable(x) for x in deterministic],indent=2,sort_keys=True))
        complexity=complexity_report(Path("."))
        (target/"complexity"/"core_complexity.json").write_text(json.dumps(complexity,indent=2,sort_keys=True))
        live_document={}
        live_file=target/"live_models"/"summary.json"
        if live_file.exists(): live_document=json.loads(live_file.read_text())
        if live_document.get("selected_ids"):
            (target/"corpus"/"live_subset_manifest.json").write_text(json.dumps({
                "frozen":True,"scenario_ids":live_document["selected_ids"],
                "models":live_document.get("models",[]),
                "modes":live_document.get("modes",[]),"trials_per_cell":1,
                "selection":"first two malicious and first two benign in corpus order"
            },indent=2,sort_keys=True))
        from .stage7 import wilson_interval
        for row in live_document.get("reliability",[]):
            low,high=wilson_interval(row["valid"],row["total"])
            row["parse_success_ci95_low"],row["parse_success_ci95_high"]=low,high
        stage9={"recall":.7916666666666666,"fpr":0.0,"f1":.8837209302325582,
                "persistent_compromise":.20833333333333334,"benign_completion":1.0}
        artifacts=generate_stage10_artifacts(deterministic=deterministic,
            stage9_metrics=stage9,reliability=live_document.get("reliability",[]),
            security=live_document.get("security",[]),failures=live_document.get("parse_failures",[]),
            multi_turn=live_document.get("multi_turn",[]),latency=live_document.get("latency",[]),
            live_false_negatives=live_document.get("false_negatives",[]),complexity=complexity,output_dir=target)
        confidence={}
        for result in deterministic:
            c=result.confusion
            for metric,count,total in (("recall",c.tp,c.tp+c.fn),("fpr",c.fp,c.fp+c.tn),
                ("persistent_compromise",sum(t.state_persisted for t in result.trials if t.malicious),sum(t.malicious for t in result.trials)),
                ("external_leakage",sum(t.external_leakage for t in result.trials if t.malicious),sum(t.malicious for t in result.trials)),
                ("benign_completion",sum(t.policy_allowed is True for t in result.trials if not t.malicious),sum(not t.malicious for t in result.trials))):
                low,high=wilson_interval(count,total);confidence[f"{result.policy}:{metric}"]={"count":count,"denominator":total,"percentage":count/total if total else None,"ci95_low":low,"ci95_high":high}
        summary={"corpus":{"malicious":len(malicious),"benign":len(benign),
            "attack_family_counts":_counts(x.scenario.attack_family for x in malicious),
            "stage9_id_overlap":0},"deterministic":[serializable(x) for x in deterministic],
            "stage9_comparison":stage9,"confidence_intervals":confidence,
            "live":live_document,"complexity":complexity}
        (target/"deterministic"/"summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True))
        (target/"report"/"stage10_summary.md").write_text("# Stage 10 summary\n\nSee `../deterministic/summary.json` and generated tables.\n")
        (target/"report"/"limitations.md").write_text("# Limitations\n\nFrozen handcrafted corpora, local-model interface failures, simulated effects, and an in-memory non-durable runtime limit external validity.\n")
        print(json.dumps({"summary":str(target/"deterministic"/"summary.json"),"artifacts":len(artifacts)},indent=2)); return

    if args.area == "evaluate" and args.command == "stage9":
        from .policy import PolicyV1, PolicyV2
        from .provenance import RuntimeSourceType
        from .stage7 import wilson_interval
        from .stage8 import IndependentPolicyHarness, IndependentScenario
        from .stage9 import (
            adversarial_split, analyze_stage8_false_negatives, evaluate_policy,
            false_negative_summary, hard_benign_corpus,
            multi_turn_lineage_comparison, policy_v1_v2_comparison,
            run_ablation_study, serializable,
        )
        from .stage9_reporting import generate_stage9_artifacts
        target = root / "stage9"; target.mkdir(parents=True, exist_ok=True)
        false_negatives = analyze_stage8_false_negatives()
        taxonomy = false_negative_summary(false_negatives)
        development = policy_v1_v2_comparison("development")
        held_out = policy_v1_v2_comparison("held_out")  # PolicyV2 frozen above.
        hard = hard_benign_corpus()
        hard_results = tuple(evaluate_policy(policy, hard, split="hard_benign")
                             for policy in (PolicyV1(), PolicyV2()))
        ablations = run_ablation_study()
        multi_turn = multi_turn_lineage_comparison()
        live_rows = []
        stage9_live_path = target / "live_raw.json"
        live_path = root / "structured_output" / "raw_results.json"
        if stage9_live_path.exists():
            grouped = {}
            for record in json.loads(stage9_live_path.read_text()):
                scenario = IndependentScenario(
                    record["scenario_id"], record["attack_family"], record["malicious"],
                    record["raw_output"], RuntimeSourceType(record["runtime_source_type"]))
                grouped.setdefault(record["model"], []).append((scenario, record))
            for model, pairs in sorted(grouped.items()):
                for policy in (PolicyV1(), PolicyV2()):
                    start = time.perf_counter_ns()
                    result = evaluate_policy(policy, [item[0] for item in pairs], split="live")
                    runtime = time.perf_counter_ns() - start
                    live_rows.append({"model": model, "policy": result.policy_name,
                        "total": len(pairs),
                        "evaluable": result.confusion.tp + result.confusion.fn
                                     + result.confusion.fp + result.confusion.tn,
                        "parse_success": sum(t.policy_allowed is not None for t in result.trials) / len(pairs),
                        "model_compromise": result.pipeline.model_compromise_rate,
                        "recall": result.confusion.recall,
                        "fpr": result.confusion.false_positive_rate,
                        "containment": result.pipeline.containment_given_rejection,
                        "persistent_compromise": result.pipeline.persistent_compromise_rate,
                        "external_leakage": result.pipeline.external_leakage_rate,
                        "benign_completion": result.pipeline.benign_completion_rate,
                        "false_rejection": result.pipeline.benign_false_rejection_rate,
                        "mean_model_generation_ns": sum(item[1]["model_generation_ns"] for item in pairs) / len(pairs),
                        "mean_policy_runtime_ns": runtime / len(pairs),
                        "mean_end_to_end_ns": (sum(item[1]["model_generation_ns"] for item in pairs) + runtime) / len(pairs)})
        elif live_path.exists():
            grouped = {}
            for record in _load_trials(live_path):
                if record.mode != "transactional": continue
                scenario = IndependentScenario(
                    f"s9-live-{record.model}-{record.scenario_id}",
                    record.attack_family or "benign", record.attack_family is not None,
                    record.raw_model_response,
                    RuntimeSourceType.RETRIEVED_CONTENT
                    if record.runtime_provenance == "retrieved_content"
                    else RuntimeSourceType.USER_PROMPT)
                grouped.setdefault(record.model, []).append(scenario)
            for model, scenarios in sorted(grouped.items()):
                for policy in (PolicyV1(), PolicyV2()):
                    result = evaluate_policy(policy, scenarios, split="live")
                    live_rows.append({"model": model, "policy": result.policy_name,
                        "evaluable": result.confusion.tp + result.confusion.fn
                                     + result.confusion.fp + result.confusion.tn,
                        "recall": result.confusion.recall,
                        "fpr": result.confusion.false_positive_rate,
                        "persistent_compromise": result.pipeline.persistent_compromise_rate,
                        "external_leakage": result.pipeline.external_leakage_rate,
                        "benign_completion": result.pipeline.benign_completion_rate})
        artifacts = generate_stage9_artifacts(
            false_negatives=false_negatives, fn_summary=taxonomy,
            development=development, held_out=held_out, ablations=ablations,
            hard_benign=hard_results, multi_turn=multi_turn,
            live_results=live_rows, output_dir=target)
        def interval(count, total):
            low, high = wilson_interval(count, total)
            return {"count": count, "denominator": total,
                    "percentage": count / total if total else 0.0,
                    "ci95_low": low, "ci95_high": high}
        summary = {"false_negatives": [serializable(x) for x in false_negatives],
                   "false_negative_summary": [serializable(x) for x in taxonomy],
                   "development": [serializable(x) for x in development],
                   "held_out": [serializable(x) for x in held_out],
                   "ablations": [serializable(x) for x in ablations],
                   "hard_benign": [serializable(x) for x in hard_results],
                   "multi_turn": [serializable(x) for x in multi_turn],
                   "live_results": live_rows,
                   "confidence_intervals": {}}
        for group_name, evaluations in (("development", development),
                                        ("held_out", held_out)):
            for evaluation in evaluations:
                c = evaluation.confusion
                summary["confidence_intervals"][f"{group_name}:{evaluation.policy_name}:recall"] = interval(c.tp, c.tp + c.fn)
                summary["confidence_intervals"][f"{group_name}:{evaluation.policy_name}:fpr"] = interval(c.fp, c.fp + c.tn)
        summary_path = target / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True))
        print(json.dumps({"summary": str(summary_path), "artifacts": len(artifacts)}, indent=2))
        return

    if args.area == "evaluate" and args.command == "stage8":
        from .stage8 import (
            IndependentPolicyHarness, as_serializable, benign_policy_corpus,
            confusion_metrics, pipeline_metrics, policy_evasion_corpus,
            IndependentScenario,
            run_failure_injection_matrix, run_multi_turn_experiments,
            run_resource_budget_attacks, semantic_poisoning_corpus,
            real_model_overhead,
        )
        from .provenance import RuntimeSourceType
        from .stage8_reporting import generate_stage8_artifacts
        target = root / "stage8"
        target.mkdir(parents=True, exist_ok=True)
        scenarios = (policy_evasion_corpus() + semantic_poisoning_corpus()
                     + benign_policy_corpus())
        trials = [IndependentPolicyHarness().run(scenario) for scenario in scenarios]
        multi_turn = run_multi_turn_experiments()
        budgets = run_resource_budget_attacks()
        failures = run_failure_injection_matrix()
        overhead = ()
        live_summary = {}
        live_path = root / "structured_output" / "raw_results.json"
        if live_path.exists():
            live_records = _load_trials(live_path)
            overhead = real_model_overhead(live_records)
            grouped = {}
            for record in live_records:
                if record.mode != "transactional":
                    continue
                scenario = IndependentScenario(
                    f"live-{record.model}-{record.scenario_id}",
                    record.attack_family or "benign", record.attack_family is not None,
                    record.raw_model_response,
                    (RuntimeSourceType.RETRIEVED_CONTENT
                     if record.runtime_provenance == "retrieved_content"
                     else RuntimeSourceType.USER_PROMPT),
                )
                grouped.setdefault(record.model, []).append(
                    IndependentPolicyHarness().run(scenario))
            live_document = {}
            for model, model_trials in grouped.items():
                live_document[model] = {
                    "trials": [as_serializable(value) for value in model_trials],
                    "confusion_metrics": as_serializable(confusion_metrics(model_trials)),
                    "pipeline_metrics": as_serializable(pipeline_metrics(model_trials)),
                }
            (target / "live_independent_policy.json").write_text(
                json.dumps(live_document, indent=2, sort_keys=True))
            live_summary = {model: {key: value for key, value in document.items()
                                    if key != "trials"}
                            for model, document in live_document.items()}
        artifacts = generate_stage8_artifacts(
            trials, multi_turn=multi_turn, budgets=budgets, failures=failures,
            overhead=overhead, output_dir=target)
        summary = {
            "trials": [as_serializable(value) for value in trials],
            "confusion_metrics": as_serializable(confusion_metrics(trials)),
            "pipeline_metrics": as_serializable(pipeline_metrics(trials)),
            "multi_turn": [as_serializable(value) for value in multi_turn],
            "resource_budgets": [as_serializable(value) for value in budgets],
            "failure_matrix": [as_serializable(value) for value in failures],
            "real_model_overhead": [as_serializable(value) for value in overhead],
            "live_independent_policy_summary": live_summary,
        }
        summary_path = target / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True))
        print(json.dumps({"summary": str(summary_path), "artifacts": len(artifacts)},
                         indent=2))
        return

    if args.area == "evaluate" and args.command == "corpus":
        malicious, benign = expanded_malicious_corpus(), expanded_benign_corpus()
        print(json.dumps({
            "malicious": len(malicious), "benign": len(benign),
            "attack_families": _counts(s.attack_family for s in malicious),
            "benign_categories": _counts(s.metadata["benign_category"] for s in benign),
        }, indent=2, sort_keys=True))
        return
    if args.area == "evaluate" and args.command == "deterministic":
        harness = EvaluationHarness()
        records = [harness.run(scenario, mode)[0]
                   for scenario in expanded_malicious_corpus() + expanded_benign_corpus()
                   for mode in EvaluationMode]
        paths = export_trial_records(records, root / "deterministic_stage7",
                                     metadata=reproducibility_metadata())
        (root / "deterministic_stage7" / "paired_comparisons.json").write_text(
            json.dumps(paired_comparisons(records), indent=2, sort_keys=True))
        print(json.dumps({key: str(value) for key, value in paths.items()}, indent=2))
        return
    if args.area == "evaluate" and args.command in {"models", "structured-output"}:
        config = LiveEvaluationConfiguration(
            models=tuple(ModelConfiguration(name, name.split(":", 1)[0])
                         for name in args.models),
            trials=args.trials,
            malicious_limit=(args.malicious_limit if args.command == "models" else 5),
            benign_limit=(args.benign_limit if args.command == "models" else 5),
            prompt_configurations=(
                ("strict_json",) if args.command == "models"
                else ("explicit_schema",)
            ),
        )
        records, availability = run_live_model_matrix(config)
        target = root / ("live_models" if args.command == "models" else "structured_output")
        export_trial_records(records, target, metadata={
            **reproducibility_metadata(),
            "availability": [asdict(item) for item in availability],
        })
        if args.command == "structured-output":
            (target / "summary.json").write_text(json.dumps(
                structured_output_summary(records), indent=2, sort_keys=True))
        print(json.dumps([asdict(item) for item in availability], indent=2))
        return
    if args.area == "benchmark":
        config = SnapshotMatrixConfiguration(
            sizes=tuple(args.sizes) if args.sizes else SnapshotMatrixConfiguration().sizes,
            iterations=args.iterations,
        )
        results = run_snapshot_matrix(config)
        paths = export_snapshot_matrix(
            results, root / "snapshot_matrix", snapshot_crossover_analysis(results))
        print(json.dumps({key: str(value) for key, value in paths.items()}, indent=2))
        return
    if args.area == "report":
        records = _load_trials(root / "deterministic_stage7" / "raw_results.json")
        snapshots = _load_snapshots(root / "snapshot_matrix" / "raw_results.json")
        paths = generate_plots(records, snapshots, root / "figures")
        generate_tables(records, snapshots, root / "report")
        write_research_report(records, snapshots, root / "report", {"source": "exported results"})
        print("\n".join(str(path) for path in paths))


def _counts(values):
    output = {}
    for value in values:
        output[value] = output.get(value, 0) + 1
    return output


def _load_trials(path: Path):
    from .evaluation import PerformanceRecord, TrialRecord
    values = json.loads(path.read_text())
    return [TrialRecord(**{**value, "performance": PerformanceRecord(**value["performance"]),
                           "claimed_provenance": tuple(value["claimed_provenance"])})
            for value in values]


def _load_snapshots(path: Path):
    from .benchmark import BenchmarkResult, MetricSummary
    document = json.loads(path.read_text())
    return [BenchmarkResult(**{
        **value,
        "phase_metrics": {key: MetricSummary(**metric)
                          for key, metric in value["phase_metrics"].items()},
    }) for value in document["results"]]


if __name__ == "__main__":
    main()
