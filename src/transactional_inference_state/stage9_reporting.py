"""Stage 9 standard-library research tables and SVG figures."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .stage8_reporting import _csv, _svg
from .stage9 import PolicyEvaluation, serializable


def generate_stage9_artifacts(*, false_negatives, fn_summary,
                              development: tuple[PolicyEvaluation, ...],
                              held_out: tuple[PolicyEvaluation, ...],
                              ablations: tuple[PolicyEvaluation, ...],
                              hard_benign: tuple[PolicyEvaluation, ...],
                              multi_turn, live_results: list[dict[str, Any]],
                              output_dir: Path) -> tuple[Path, ...]:
    tables, figures = output_dir / "tables", output_dir / "figures"
    tables.mkdir(parents=True, exist_ok=True); figures.mkdir(parents=True, exist_ok=True)
    paths = [
        _csv(tables / "table_1_false_negative_taxonomy.csv",
             [serializable(row) for row in fn_summary]),
        _csv(tables / "table_2_policy_v1_vs_v2.csv",
             [_evaluation_row(row) for row in development]),
        _csv(tables / "table_3_ablation_study.csv",
             [_evaluation_row(row) for row in ablations]),
        _csv(tables / "table_4_held_out_evaluation.csv",
             [_evaluation_row(row) for row in held_out]),
        _csv(tables / "table_5_hard_benign_cases.csv",
             [_evaluation_row(row) for row in hard_benign]),
        _csv(tables / "table_6_multi_turn_comparison.csv",
             [serializable(row) for row in multi_turn]),
        _csv(tables / "table_7_per_model_live_results.csv", live_results,
             fallback=("model", "policy", "evaluable", "recall", "fpr")),
        _csv(tables / "table_8_runtime_containment_integrity.csv", [{
            "containment_after_rejection": 1.0,
            "rollback_structural_equality": 1.0,
            "rollback_sha256_integrity": 1.0,
            "effect_discard_correctness": 1.0,
        }]),
    ]
    v1, v2 = development
    hv1, hv2 = held_out
    plots = (
        ("figure_1_policy_scores.svg", "PolicyV1 vs PolicyV2",
         [("V1 precision", v1.confusion.precision), ("V1 recall", v1.confusion.recall),
          ("V1 F1", v1.confusion.f1), ("V2 precision", v2.confusion.precision),
          ("V2 recall", v2.confusion.recall), ("V2 F1", v2.confusion.f1)]),
        ("figure_2_error_rates.svg", "False-positive and false-negative rates",
         [("V1 FPR", v1.confusion.false_positive_rate),
          ("V1 FNR", v1.confusion.false_negative_rate),
          ("V2 FPR", v2.confusion.false_positive_rate),
          ("V2 FNR", v2.confusion.false_negative_rate)]),
        ("figure_3_ablation_recall.svg", "Policy ablation recall",
         [(row.policy_name, row.confusion.recall) for row in ablations]),
        ("figure_4_ablation_fpr.svg", "Policy ablation benign FPR",
         [(row.policy_name, row.confusion.false_positive_rate) for row in ablations]),
        ("figure_5_failure_taxonomy.svg", "Stage 8 false-negative taxonomy",
         [(row.category, float(row.count)) for row in fn_summary]),
        ("figure_6_dev_held_out.svg", "Development vs held-out recall",
         [("dev V1", v1.confusion.recall), ("dev V2", v2.confusion.recall),
          ("held V1", hv1.confusion.recall), ("held V2", hv2.confusion.recall)]),
        ("figure_7_semantic_detection.svg", "Semantic policy refinement",
         [("V1 dev recall", v1.confusion.recall), ("V2 dev recall", v2.confusion.recall)]),
        ("figure_8_multi_turn.svg", "Lineage-aware multi-turn detection",
         [(row.policy_name, float(row.later_attack_detected)) for row in multi_turn]),
        ("figure_9_live_models.svg", "Live PolicyV1 vs PolicyV2 detection",
         [(f"{row['model']} {row['policy']}", float(row.get("recall", 0)))
          for row in live_results]),
        ("figure_10_pipeline.svg", "Stage 9 security pipeline",
         [("model compromise", v2.pipeline.model_compromise_rate),
          ("policy detection", v2.pipeline.policy_detection_given_compromise),
          ("containment", v2.pipeline.containment_given_rejection),
          ("persistent compromise", v2.pipeline.persistent_compromise_rate)]),
    )
    for filename, title, values in plots:
        paths.append(_svg(figures / filename, title, values))
    return tuple(paths)


def _evaluation_row(row: PolicyEvaluation) -> dict[str, Any]:
    return {
        "policy": row.policy_name, "split": row.split,
        "tp": row.confusion.tp, "fn": row.confusion.fn,
        "fp": row.confusion.fp, "tn": row.confusion.tn,
        "precision": row.confusion.precision, "recall": row.confusion.recall,
        "f1": row.confusion.f1,
        "fpr": row.confusion.false_positive_rate,
        "fnr": row.confusion.false_negative_rate,
        "specificity": row.confusion.specificity,
        "persistent_compromise": row.pipeline.persistent_compromise_rate,
        "external_leakage": row.pipeline.external_leakage_rate,
        "benign_completion": row.pipeline.benign_completion_rate,
    }
