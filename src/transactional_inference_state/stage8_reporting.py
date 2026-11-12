"""Standard-library Stage 8 table and publication-readable SVG exports."""
from __future__ import annotations

import csv
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from .stage8 import (
    IndependentTrial, confusion_metrics, pipeline_metrics, as_serializable,
)


def generate_stage8_artifacts(trials: Iterable[IndependentTrial], *,
                              multi_turn: Iterable[Any], budgets: Iterable[Any],
                              failures: Iterable[Any], overhead: Iterable[Any],
                              output_dir: Path) -> tuple[Path, ...]:
    trials, multi_turn = list(trials), list(multi_turn)
    budgets, failures, overhead = list(budgets), list(failures), list(overhead)
    output_dir.mkdir(parents=True, exist_ok=True)
    metrics, pipeline = confusion_metrics(trials), pipeline_metrics(trials)
    tables = output_dir / "tables"
    figures = output_dir / "figures"
    tables.mkdir(exist_ok=True); figures.mkdir(exist_ok=True)
    paths = [
        _csv(tables / "table_1_policy_confusion_matrix.csv", [
            {"classification": key.upper(), "count": getattr(metrics, key)}
            for key in ("tp", "fn", "fp", "tn")]),
        _csv(tables / "table_2_policy_metrics.csv", [
            {"metric": key, "value": getattr(metrics, key)} for key in
            ("precision", "recall", "f1", "false_positive_rate",
             "false_negative_rate", "specificity")]),
        _csv(tables / "table_3_pipeline_security.csv", [
            {"metric": key, "value": value}
            for key, value in asdict(pipeline).items()]),
        _csv(tables / "table_4_multi_turn_attacks.csv",
             [as_serializable(value) for value in multi_turn]),
        _csv(tables / "table_5_resource_budget_enforcement.csv",
             [as_serializable(value) for value in budgets]),
        _csv(tables / "table_6_failure_injection_matrix.csv",
             [as_serializable(value) for value in failures]),
        _csv(tables / "table_7_real_model_overhead.csv",
             [as_serializable(value) for value in overhead],
             fallback=("model", "pairs", "mean_model_generation_ns",
                       "mean_transaction_runtime_ns", "mean_end_to_end_ns",
                       "transaction_overhead_fraction")),
        _csv(tables / "table_8_capability_violations.csv", _reason_rows(trials)),
    ]
    plots = (
        ("figure_1_pipeline.svg", "Model → policy → containment",
         [("compromise", pipeline.model_compromise_rate),
          ("detected", pipeline.policy_detection_given_compromise),
          ("contained", pipeline.containment_given_rejection)]),
        ("figure_2_policy_scores.svg", "Policy precision / recall / F1",
         [("precision", metrics.precision), ("recall", metrics.recall),
          ("F1", metrics.f1)]),
        ("figure_3_error_rates.svg", "Policy error rates",
         [("false positive", metrics.false_positive_rate),
          ("false negative", metrics.false_negative_rate)]),
        ("figure_4_persistence_family.svg", "Persistent compromise by family",
         _family_rates(trials, "state_persisted")),
        ("figure_5_semantic_structural.svg", "Semantic vs structural detection",
         _detection_groups(trials)),
        ("figure_6_multi_turn.svg", "Multi-turn attack outcomes",
         [("seed persisted", _rate(multi_turn, "seed_committed")),
          ("later detected", _rate(multi_turn, "policy_detected_later_attack")),
          ("persistent", _rate(multi_turn, "persistent_compromise"))]),
        ("figure_7_resource_budgets.svg", "Resource budget rejection",
         [(row.attack, float(row.rejected)) for row in budgets]),
        ("figure_8_latency.svg", "Real-model latency breakdown",
         [(row.model, row.mean_transaction_runtime_ns / 1e6) for row in overhead]),
        ("figure_9_overhead_fraction.svg", "Transaction overhead (% end-to-end)",
         [(row.model, row.transaction_overhead_fraction) for row in overhead]),
        ("figure_10_failures.svg", "Failure injection visible effects",
         [(row.failure_point, float(row.internal_state_visible or row.effects_visible))
          for row in failures]),
    )
    for filename, title, values in plots:
        paths.append(_svg(figures / filename, title, values))
    return tuple(paths)


def _csv(path: Path, rows: list[dict[str, Any]], fallback: tuple[str, ...] = ()) -> Path:
    fields = tuple(rows[0]) if rows else fallback
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)
    return path


def _reason_rows(trials: list[IndependentTrial]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for trial in trials:
        for reason in trial.policy_reasons:
            counts[reason] = counts.get(reason, 0) + 1
    return [{"reason": key, "count": value} for key, value in sorted(counts.items())]


def _family_rates(trials: list[IndependentTrial], attribute: str) -> list[tuple[str, float]]:
    families = sorted({trial.attack_family for trial in trials if trial.malicious})
    return [(family, sum(bool(getattr(t, attribute)) for t in trials
                         if t.attack_family == family) /
             sum(t.attack_family == family for t in trials)) for family in families]


def _detection_groups(trials: list[IndependentTrial]) -> list[tuple[str, float]]:
    semantic = {"trust_paraphrase", "semantic_memory_poisoning",
                "allowed_operation_abuse", "distributed_intent", "split_operations"}
    groups = {"semantic": [t for t in trials if t.attack_family in semantic],
              "structural": [t for t in trials if t.malicious and t.attack_family not in semantic]}
    return [(name, sum(t.policy_allowed is False for t in rows) / len(rows) if rows else 0)
            for name, rows in groups.items()]


def _rate(rows: list[Any], field: str) -> float:
    return sum(bool(getattr(row, field)) for row in rows) / len(rows) if rows else 0.0


def _svg(path: Path, title: str, values: list[tuple[str, float]]) -> Path:
    values = values or [("unavailable", 0.0)]
    maximum = max((value for _, value in values), default=1.0) or 1.0
    width, row_height = 900, 38
    height = 70 + row_height * len(values)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
             '<rect width="100%" height="100%" fill="white"/>',
             f'<text x="20" y="30" font-family="sans-serif" font-size="18">{_escape(title)}</text>']
    for index, (label, value) in enumerate(values):
        y = 52 + index * row_height
        bar = 600 * max(0.0, value) / maximum
        parts.extend((
            f'<text x="20" y="{y + 17}" font-family="sans-serif" font-size="12">{_escape(str(label)[:34])}</text>',
            f'<rect x="250" y="{y}" width="{bar:.2f}" height="22" fill="#3569a8"/>',
            f'<text x="{260 + bar:.2f}" y="{y + 16}" font-family="sans-serif" font-size="12">{value:.3f}</text>',
        ))
    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")
    return path


def _escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
