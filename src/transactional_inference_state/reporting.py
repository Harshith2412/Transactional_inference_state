"""Stage 7 result export, tables, and result-driven plotting."""
from __future__ import annotations

from dataclasses import asdict
import csv
import json
from pathlib import Path
from typing import Any, Iterable

from .benchmark import BenchmarkResult
from .evaluation import TrialOutcome, TrialRecord
from .stage7 import latency_summary, parse_failure_category, security_summary


def _flatten_trial(record: TrialRecord) -> dict[str, Any]:
    value = record.to_dict()
    performance = value.pop("performance")
    value.update(performance)
    value["claimed_provenance"] = "|".join(value["claimed_provenance"])
    return value


def export_trial_records(records: Iterable[TrialRecord], directory: str | Path,
                         *, metadata: dict[str, Any] | None = None) -> dict[str, Path]:
    records = list(records)
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    raw_json, raw_csv = target / "raw_results.json", target / "raw_results.csv"
    summary_json = target / "aggregates.json"
    raw_json.write_text(json.dumps([record.to_dict() for record in records],
                                   indent=2, sort_keys=True), encoding="utf-8")
    flattened = [_flatten_trial(record) for record in records]
    if flattened:
        with raw_csv.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(flattened[0]))
            writer.writeheader()
            writer.writerows(flattened)
    summary_json.write_text(json.dumps({
        "metadata": metadata or {},
        "groups": security_summary(records),
    }, indent=2, sort_keys=True), encoding="utf-8")
    return {"raw_json": raw_json, "raw_csv": raw_csv, "aggregates": summary_json}


def structured_output_summary(records: Iterable[TrialRecord]) -> list[dict[str, Any]]:
    records = list(records)
    keys = sorted({(record.model, record.prompt_configuration) for record in records})
    rows = []
    for model, prompt in keys:
        all_group = [record for record in records
                     if record.model == model and record.prompt_configuration == prompt]
        unavailable = [record for record in all_group
                       if record.outcome == TrialOutcome.MODEL_UNAVAILABLE.value]
        group = [record for record in all_group
                 if record.outcome != TrialOutcome.MODEL_UNAVAILABLE.value]
        if not group:
            rows.append({"model": model, "prompt_configuration": prompt,
                         "trials": 0, "unavailable_trials": len(unavailable),
                         "parse_success_rate": 0.0, "parse_failure_rate": 0.0,
                         "malformed_output_rate": 0.0, "unknown_operation_rate": 0.0,
                         "missing_field_rate": 0.0, "extra_field_rate": 0.0,
                         "invalid_type_rate": 0.0, "duplicate_operation_id_rate": 0.0,
                         "benign_completion_rate": 0.0,
                         "valid_schema_policy_rejection_rate": 0.0})
            continue
        failures: dict[str, int] = {}
        for record in group:
            if not record.parser_success:
                category = parse_failure_category(record.error)
                failures[category] = failures.get(category, 0) + 1
        benign = [record for record in group if record.attack_family is None]
        total = len(group)
        rows.append({
            "model": model, "prompt_configuration": prompt,
            "trials": len(group), "unavailable_trials": len(unavailable),
            "parse_success_rate": sum(r.parser_success for r in group) / total,
            "parse_failure_rate": sum(not r.parser_success for r in group) / total,
            "malformed_output_rate": failures.get("malformed_output", 0) / total,
            "unknown_operation_rate": failures.get("unknown_operation", 0) / total,
            "missing_field_rate": failures.get("missing_field", 0) / total,
            "extra_field_rate": failures.get("extra_field", 0) / total,
            "invalid_type_rate": failures.get("invalid_type", 0) / total,
            "duplicate_operation_id_rate": failures.get("duplicate_operation_id", 0) / total,
            "benign_completion_rate": (
                sum(r.benign_completion for r in benign) / len(benign) if benign else 0),
            "valid_schema_policy_rejection_rate": (
                sum(r.parser_success and not r.validation_result for r in group) / total),
            **{f"{name}_count": count for name, count in sorted(failures.items())},
        })
    return rows


def export_snapshot_matrix(results: Iterable[BenchmarkResult], directory: str | Path,
                           crossover: list[dict[str, Any]]) -> dict[str, Path]:
    results = list(results)
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    raw_json, raw_csv, summary_csv = (
        target / "raw_results.json", target / "raw_results.csv", target / "summary.csv")
    raw = [result.to_dict() for result in results]
    raw_json.write_text(json.dumps({"results": raw, "crossover": crossover},
                                   indent=2, sort_keys=True), encoding="utf-8")
    rows = []
    for result in results:
        row = {key: value for key, value in result.to_dict().items()
               if key != "phase_metrics"}
        for phase, metrics in result.to_dict()["phase_metrics"].items():
            row.update({f"{phase}_{key}": value for key, value in metrics.items()})
        rows.append(row)
    for path in (raw_csv, summary_csv):
        if rows:
            fieldnames = sorted({key for row in rows for key in row})
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
    return {"raw_json": raw_json, "raw_csv": raw_csv, "summary": summary_csv}


def _write_table(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def generate_tables(records: Iterable[TrialRecord], snapshots: Iterable[BenchmarkResult],
                    directory: str | Path) -> dict[str, Path]:
    records, snapshots = list(records), list(snapshots)
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    model_rows = security_summary(records, group_fields=("model", "mode"))
    table_a, table_b, table_c, table_d, table_e = (
        target / "table_a_model_security.csv", target / "table_b_benign_utility.csv",
        target / "table_c_attack_family.csv", target / "table_d_snapshot.csv",
        target / "table_e_structured_output.csv",
    )
    security_rows, benign_rows = [], []
    for row in model_rows:
        matching_benign = [record for record in records
                           if record.model == row["model"] and record.mode == row["mode"]
                           and record.attack_family is None
                           and record.outcome != TrialOutcome.MODEL_UNAVAILABLE.value]
        security_rows.append({
            "model": row["model"], "mode": row["mode"],
            "malicious_trials": row["malicious_trials"],
            "model_compromise_rate": row["model_compromise"]["rate"],
            "containment_given_compromise": row["containment_given_compromise"]["rate"],
            "persistent_compromise_rate": row["persistent_compromise"]["rate"],
            "external_leakage_rate": row["external_leakage"]["rate"],
            "rollback_integrity": row["rollback_integrity"]["rate"],
        })
        benign_rows.append({
            "model": row["model"], "mode": row["mode"],
            "benign_trials": row["benign_trials"],
            "parse_success": row["parse_success"]["rate"],
            "completion_rate": row["benign_completion"]["rate"],
            "false_rejection": row["benign_false_rejection"]["rate"],
            "expected_state_correctness": _mean_bool([
                record.expected_state_update_correct for record in matching_benign]),
            "expected_effect_correctness": _mean_bool([
                record.expected_effect_execution_correct for record in matching_benign]),
        })
    family_rows = security_summary(
        [record for record in records if record.attack_family is not None],
        group_fields=("model", "mode", "attack_family"))
    family_flat = [{
        "model": row["model"], "mode": row["mode"],
        "attack_family": row["attack_family"],
        "trials": row["malicious_trials"],
        "model_compromise_rate": row["model_compromise"]["rate"],
        "persistent_compromise_rate": row["persistent_compromise"]["rate"],
        "containment_given_compromise": row["containment_given_compromise"]["rate"],
    } for row in family_rows]
    snapshot_rows = [{
        "strategy": result.strategy, "state_size_bytes": result.state_size_bytes,
        "mutation_ratio": result.mutation_ratio, "operation": result.operation_type,
        "iterations": result.iterations, "mean_latency_ns": result.mean_latency_ns,
        "median_latency_ns": result.median_latency_ns,
        "peak_traced_python_allocation_bytes": result.mean_memory_overhead_bytes,
        "integrity": result.rollback_integrity,
    } for result in snapshots]
    _write_table(table_a, security_rows)
    _write_table(table_b, benign_rows)
    _write_table(table_c, family_flat)
    _write_table(table_d, snapshot_rows)
    _write_table(table_e, structured_output_summary(records))

    markdown = target / "tables.md"
    sections = []
    for title, rows in (("Table A — Per-model security", security_rows),
                        ("Table B — Benign utility", benign_rows),
                        ("Table C — Attack families", family_flat),
                        ("Table D — Snapshot strategies", snapshot_rows),
                        ("Table E — Structured output", structured_output_summary(records))):
        sections.append(f"## {title}\n")
        if rows:
            columns = list(rows[0])
            sections.extend(("| " + " | ".join(columns) + " |",
                             "| " + " | ".join("---" for _ in columns) + " |"))
            sections.extend("| " + " | ".join(str(row.get(column, ""))
                                                for column in columns) + " |"
                            for row in rows)
        sections.append("")
    markdown.write_text("\n".join(sections), encoding="utf-8")
    return {"table_a": table_a, "table_b": table_b, "table_c": table_c,
            "table_d": table_d, "table_e": table_e, "markdown": markdown}


def generate_plots(records: Iterable[TrialRecord], snapshots: Iterable[BenchmarkResult],
                   directory: str | Path) -> list[Path]:
    """Generate ten SVG figures from actual records using matplotlib."""
    try:
        import matplotlib.pyplot as plt
    except ImportError as error:
        raise RuntimeError("matplotlib is required to generate figures") from error
    records, snapshots = list(records), list(snapshots)
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    paths = []

    def save(number: int, slug: str) -> None:
        path = target / f"figure_{number:02d}_{slug}.svg"
        plt.tight_layout()
        plt.savefig(path, format="svg", bbox_inches="tight")
        plt.close()
        paths.append(path)

    modes = ("baseline", "transactional")
    malicious = {mode: [r for r in records if r.mode == mode and r.attack_family]
                 for mode in modes}
    metrics = [
        [sum(r.persistent_compromise for r in malicious[m]) / len(malicious[m]) for m in modes],
        [sum(r.external_effect_leakage for r in malicious[m]) / len(malicious[m]) for m in modes],
        [sum(not r.persistent_compromise and not r.external_effect_leakage
             for r in malicious[m]) / len(malicious[m]) for m in modes],
    ]
    _grouped_bars(plt, modes, metrics, ["Persistent", "External leakage", "Containment"],
                  "Baseline vs Transactional Security", "Rate")
    save(1, "security")

    models = sorted({r.model for r in records})
    per_model = []
    for metric in ("model_compromise", "runtime_containment_success", "persistent_compromise"):
        per_model.append([_mean_bool([getattr(r, metric) for r in records
                                     if r.model == model and r.attack_family]) for model in models])
    _grouped_bars(plt, models, per_model,
                  ["Model compromise", "Containment given observed trials", "Persistent"],
                  "Per-Model Compromise and Containment", "Rate")
    save(2, "model_compromise")

    benign = {model: [r for r in records if r.model == model and not r.attack_family]
              for model in models}
    utility = [[_mean_bool([r.benign_completion for r in benign[m]]) for m in models],
               [_mean_bool([not r.validation_result for r in benign[m]]) for m in models],
               [_mean_bool([r.parser_success for r in benign[m]]) for m in models]]
    _grouped_bars(plt, models, utility, ["Completion", "False rejection", "Parse success"],
                  "Benign Utility by Model", "Rate")
    save(3, "benign_utility")

    families = sorted({r.attack_family for r in records if r.attack_family})
    family_metrics = [[_mean_bool([getattr(r, metric) for r in records
                                   if r.attack_family == family]) for family in families]
                      for metric in ("model_compromise", "persistent_compromise",
                                     "runtime_containment_success")]
    _grouped_bars(plt, families, family_metrics,
                  ["Model compromise", "Persistent", "Containment"],
                  "Attack Family Breakdown", "Rate", rotate=True)
    save(4, "attack_families")

    reliability = structured_output_summary(records)
    labels = [f"{r['model']}\n{r['prompt_configuration']}" for r in reliability]
    rel_metrics = [[r[key] for r in reliability] for key in
                   ("parse_success_rate", "malformed_output_rate", "benign_completion_rate")]
    _grouped_bars(plt, labels, rel_metrics, ["Parse success", "Parse failure", "Benign completion"],
                  "Structured Output Reliability", "Rate", rotate=True)
    save(5, "structured_output")

    latency = [[statistics_mean([r.performance.total_runtime_ns for r in records if r.mode == mode])
                for mode in modes],
               [statistics_mean([r.performance.transaction_runtime_ns for r in records if r.mode == mode])
                for mode in modes],
               [statistics_mean([r.performance.model_generation_ns for r in records if r.mode == mode])
                for mode in modes]]
    _grouped_bars(plt, modes, latency, ["Total", "Runtime", "Model generation"],
                  "Execution Latency Components", "Latency (ns)")
    save(6, "overhead")

    for number, operation in ((7, "commit"), (8, "rollback")):
        _snapshot_line_plot(plt, snapshots, operation, "state_size_bytes",
                            f"{operation.title()} Latency vs State Size", "State size (bytes)")
        save(number, f"{operation}_state_size")
    _snapshot_line_plot(plt, snapshots, "commit", "mutation_ratio",
                        "Commit Latency vs Mutation Ratio", "Mutation ratio")
    save(9, "mutation_ratio")
    plt.figure(figsize=(7, 4.5))
    for strategy in ("full_copy", "delta"):
        selected = sorted([r for r in snapshots if r.strategy == strategy
                           and r.operation_type == "commit" and r.mutation_ratio == 0.05],
                          key=lambda r: r.state_size_bytes)
        plt.plot([r.state_size_bytes for r in selected],
                 [r.mean_memory_overhead_bytes for r in selected], marker="o", label=strategy)
    plt.xscale("log")
    plt.xlabel("State size (bytes)")
    plt.ylabel("Peak traced Python allocation (bytes; not RSS)")
    plt.title("Traced Allocation vs State Size")
    plt.legend()
    save(10, "traced_memory")
    return paths


def _mean_bool(values: list[bool]) -> float:
    return sum(values) / len(values) if values else 0.0


def statistics_mean(values: list[int]) -> float:
    return sum(values) / len(values) if values else 0.0


def _grouped_bars(plt: Any, labels: Iterable[str], series: list[list[float]],
                  series_labels: list[str], title: str, ylabel: str,
                  rotate: bool = False) -> None:
    labels = list(labels)
    positions = list(range(len(labels)))
    width = 0.8 / max(1, len(series))
    plt.figure(figsize=(max(7, len(labels) * 0.55), 4.8))
    for index, values in enumerate(series):
        offset = (index - (len(series) - 1) / 2) * width
        plt.bar([position + offset for position in positions], values,
                width=width, label=series_labels[index])
    plt.xticks(positions, labels, rotation=45 if rotate else 0,
               ha="right" if rotate else "center")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()


def _snapshot_line_plot(plt: Any, snapshots: list[BenchmarkResult], operation: str,
                        x_field: str, title: str, xlabel: str) -> None:
    plt.figure(figsize=(7, 4.5))
    for strategy in ("full_copy", "delta"):
        selected = [r for r in snapshots if r.strategy == strategy
                    and r.operation_type == operation]
        if x_field == "state_size_bytes":
            selected = [r for r in selected if r.mutation_ratio == 0.05]
        else:
            sizes = sorted({r.state_size_bytes for r in selected})
            selected = [r for r in selected if r.state_size_bytes == sizes[len(sizes)//2]]
        selected.sort(key=lambda r: getattr(r, x_field))
        plt.plot([getattr(r, x_field) for r in selected],
                 [r.mean_latency_ns for r in selected], marker="o", label=strategy)
    if x_field == "state_size_bytes":
        plt.xscale("log")
    plt.xlabel(xlabel)
    plt.ylabel("Mean transaction latency (ns)")
    plt.title(title)
    plt.legend()


def write_research_report(records: Iterable[TrialRecord], snapshots: Iterable[BenchmarkResult],
                          directory: str | Path, configuration: dict[str, Any]) -> dict[str, Path]:
    records, snapshots = list(records), list(snapshots)
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    summary_path, limitations_path = target / "evaluation_summary.md", target / "limitations.md"
    summaries = security_summary(records)
    models = sorted({record.model for record in records})
    malicious_scenarios = {record.scenario_id for record in records if record.attack_family}
    benign_scenarios = {record.scenario_id for record in records if not record.attack_family}
    reliability = structured_output_summary(records)
    summary_path.write_text(
        "# Stage 7 evaluation summary\n\n"
        "## Experiment configuration\n\n"
        f"`{json.dumps(configuration, sort_keys=True)}`\n\n"
        f"Models: {', '.join(models)}. Raw execution records: {len(records)}. "
        f"Malicious scenarios represented: {len(malicious_scenarios)}. "
        f"Benign scenarios represented: {len(benign_scenarios)}. "
        f"Snapshot matrix cells: {len(snapshots)}.\n\n"
        "## Security and benign utility results\n\n```json\n"
        + json.dumps(summaries, indent=2, sort_keys=True) + "\n```\n\n"
        "## Structured-output reliability\n\n```json\n"
        + json.dumps(reliability, indent=2, sort_keys=True) + "\n```\n\n"
        "## Performance and snapshot results\n\n"
        "Latency distributions are included in each grouped result above. Snapshot raw "
        "phase timings, traced Python allocation, integrity, and crossover analysis are "
        "stored under `evaluation_results/snapshot_matrix/`.\n\n"
        "## Interpretation boundary\n\n"
        "These are measured observations for this corpus, configuration, local models, "
        "and environment. Model refusal and parser rejection are not counted as runtime "
        "containment. See `limitations.md`.\n",
        encoding="utf-8")
    limitations_path.write_text(
        "# Limitations\n\n"
        "- The corpus is handcrafted and attack coverage is limited.\n"
        "- Policy expectations are encoded by scenarios.\n"
        "- External effects are simulator-only.\n"
        "- Local model selection and sample sizes constrain comparison.\n"
        "- Results depend on strict-parser behavior and prompting.\n"
        "- Runtime provenance is not full taint propagation.\n"
        "- Timing and allocation measurements are hardware and interpreter dependent.\n"
        "- Execution is in-memory and single-process without crash durability.\n"
        "- There are no real distributed transactions.\n",
        encoding="utf-8")
    return {"summary": summary_path, "limitations": limitations_path}
