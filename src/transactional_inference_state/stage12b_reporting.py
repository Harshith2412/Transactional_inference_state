"""Dependency-free Stage 12B artifact, table, and SVG generation."""
from __future__ import annotations

import csv
from dataclasses import asdict
import json
from pathlib import Path
from statistics import median
from typing import Any, Iterable

from .stage12b import (
    COWBenchmarkRecord, COWCorrectnessResult, COWProvenanceOverhead,
    stage12b_complexity_report,
)


def generate_stage12b_artifacts(
    records: Iterable[COWBenchmarkRecord], *,
    rollback: COWCorrectnessResult, commit: COWCorrectnessResult,
    provenance_overhead: COWProvenanceOverhead, output: Path,
) -> dict[str, Any]:
    rows = list(records)
    for name in ("correctness", "benchmark", "provenance", "tables", "figures", "report"):
        (output / name).mkdir(parents=True, exist_ok=True)
    _json(output / "correctness/rollback_experiment.json", asdict(rollback))
    _json(output / "correctness/commit_experiment.json", asdict(commit))
    documents = [asdict(row) for row in rows]
    _json(output / "benchmark/raw_results.json", documents)
    _csv(output / "benchmark/raw_results.csv", documents)
    aggregates = _aggregates(rows)
    summary = {
        "records": len(rows),
        "primary_depth_3_records": sum(row.mutation_depth == 3 for row in rows),
        "depth_sensitivity_records": sum(row.mutation_depth != 3 for row in rows),
        "aggregates": aggregates,
        "correctness": {"rollback": asdict(rollback), "commit": asdict(commit)},
        "provenance_overhead": asdict(provenance_overhead),
        "complexity": stage12b_complexity_report(),
        "benchmark_scope": {
            "primary": "five sizes x six mutation ratios x depth 3 x three strategies x two outcomes",
            "depth_sensitivity": "100KB x ratios 1%, 10%, 100% x depths 1 and 5 x three strategies x two outcomes",
            "iterations": 1,
            "copy_metric": "estimated Python nodes copied per logically modified field",
        },
    }
    _json(output / "benchmark/summary.json", summary)
    _json(output / "provenance/field_provenance_summary.json", {
        "rollback": asdict(rollback), "commit": asdict(commit),
        "microbenchmark": asdict(provenance_overhead),
        "container_semantics": "container structure is not assigned the union of child labels",
    })
    _csv(output / "tables/table_1_strategy_summary.csv", aggregates)
    _csv(output / "tables/table_2_flagship_correctness.csv", [
        asdict(rollback), asdict(commit)
    ])
    _csv(output / "tables/table_3_provenance_overhead.csv", [
        asdict(provenance_overhead)
    ])
    _generate_figures(rows, provenance_overhead, output / "figures")
    (output / "report/stage12b_summary.md").write_text(_report(summary))
    (output / "report/limitations.md").write_text(
        "# Stage 12B limitations\n\n"
        "Synthetic in-memory benchmark; one iteration per matrix cell; node-copy "
        "accounting is strategy-aware but approximate; `tracemalloc` is not RSS; "
        "explicit COW paths only; arbitrary callbacks fully materialize; private "
        "state is field-granular while shared conflicts remain key-granular; no "
        "thread safety, durability, automatic dependency inference, or dynamic "
        "taint analysis.\n"
    )
    return summary


def _aggregates(rows: list[COWBenchmarkRecord]) -> list[dict[str, Any]]:
    primary = [row for row in rows if row.mutation_depth == 3]
    output = []
    for strategy in ("full_copy", "delta", "fine_grained_cow"):
        for outcome in ("commit", "rollback"):
            selected = [row for row in primary
                        if row.strategy == strategy and row.outcome == outcome]
            output.append({
                "strategy": strategy,
                "outcome": outcome,
                "records": len(selected),
                "median_total_ns": median(row.total_ns for row in selected),
                "median_begin_ns": median(row.begin_ns for row in selected),
                "median_read_ns": median(row.read_ns for row in selected),
                "median_mutation_ns": median(row.mutation_ns for row in selected),
                "median_validation_ns": median(row.validation_ns for row in selected),
                "median_closure_ns": median(row.closure_ns for row in selected),
                "median_peak_traced_bytes": median(row.peak_traced_bytes for row in selected),
                "median_copy_amplification": median(row.copy_amplification for row in selected),
                "rollback_integrity_rate": sum(row.rollback_integrity for row in selected) / len(selected),
                "provenance_integrity_rate": sum(row.provenance_integrity for row in selected) / len(selected),
                "full_materialization_rate": sum(row.full_materialization_occurred for row in selected) / len(selected),
            })
    return output


def _generate_figures(rows: list[COWBenchmarkRecord], overhead: COWProvenanceOverhead,
                      output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "figure_1_cow_path.svg").write_text(_path_figure())
    primary = [row for row in rows if row.mutation_depth == 3]
    size_order = ["10KB", "100KB", "1MB", "10MB", "50MB"]
    for outcome, number in (("commit", 2), ("rollback", 3)):
        series = {}
        for strategy in ("full_copy", "delta", "fine_grained_cow"):
            series[strategy] = [median(
                row.closure_ns / 1e6 for row in primary
                if row.outcome == outcome and row.strategy == strategy
                and row.state_size == size
            ) for size in size_order]
        (output / f"figure_{number}_{outcome}_latency.svg").write_text(
            _line_svg(f"{outcome.title()} latency vs state size", size_order,
                      series, "milliseconds")
        )
    amp = {strategy: [median(
        row.copy_amplification for row in primary if row.strategy == strategy
        and row.mutation_ratio == ratio
    ) for ratio in (.01, .05, .10, .25, .50, 1.0)]
        for strategy in ("full_copy", "delta", "fine_grained_cow")}
    (output / "figure_4_copy_amplification.svg").write_text(_line_svg(
        "Node copy amplification", ["1%", "5%", "10%", "25%", "50%", "100%"],
        amp, "copied nodes / modified field"))
    latency = {strategy: [median(
        row.total_ns / 1e6 for row in primary if row.strategy == strategy
        and row.mutation_ratio == ratio
    ) for ratio in (.01, .05, .10, .25, .50, 1.0)]
        for strategy in ("full_copy", "delta", "fine_grained_cow")}
    (output / "figure_5_mutation_ratio.svg").write_text(_line_svg(
        "Total latency vs mutation ratio", ["1%", "5%", "10%", "25%", "50%", "100%"],
        latency, "milliseconds"))
    depth_series = {strategy: [median(
        row.total_ns / 1e6 for row in rows if row.strategy == strategy
        and row.state_size == "100KB" and row.mutation_depth == depth
        and row.mutation_ratio in {.01, .10, 1.0}
    ) for depth in (1, 3, 5)] for strategy in (
        "full_copy", "delta", "fine_grained_cow")}
    (output / "figure_6_nesting_depth.svg").write_text(_line_svg(
        "Total latency vs nesting depth (100KB subset)", ["1", "3", "5"],
        depth_series, "milliseconds"))
    (output / "figure_7_provenance_overhead.svg").write_text(_bar_svg(
        "COW field mutation provenance overhead",
        ["COW only", "COW + provenance"],
        [overhead.mutation_without_provenance_median_ns / 1e3,
         overhead.mutation_with_provenance_median_ns / 1e3], "microseconds"))


def _line_svg(title: str, labels: list[str], series: dict[str, list[float]],
              unit: str) -> str:
    colors = {"full_copy": "#b45309", "delta": "#2563eb",
              "fine_grained_cow": "#15803d"}
    maximum = max(max(values) for values in series.values()) or 1
    left, top, width, height = 80, 65, 650, 300
    pieces = [_svg_start(title),
              f'<text x="18" y="35" class="title">{title}</text>',
              f'<text x="18" y="55" class="small">{unit}</text>',
              f'<path d="M{left} {top} V{top+height} H{left+width}" class="axis"/>']
    for index, label in enumerate(labels):
        x = left + index * width / max(1, len(labels)-1)
        pieces.append(f'<text x="{x:.1f}" y="{top+height+24}" text-anchor="middle" class="small">{label}</text>')
    for series_index, (name, values) in enumerate(series.items()):
        points=[]
        for index, value in enumerate(values):
            x=left+index*width/max(1,len(labels)-1);y=top+height-(value/maximum)*height
            points.append(f"{x:.1f},{y:.1f}")
            pieces.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="{colors[name]}"/>')
        pieces.append(f'<polyline points="{" ".join(points)}" fill="none" stroke="{colors[name]}" stroke-width="2.5"/>')
        pieces.append(f'<text x="760" y="{100+series_index*28}" class="small" fill="{colors[name]}">{name}</text>')
    return "".join(pieces)+"</svg>"


def _bar_svg(title: str, labels: list[str], values: list[float], unit: str) -> str:
    maximum=max(values) or 1; pieces=[_svg_start(title),
        f'<text x="18" y="35" class="title">{title}</text>',
        f'<text x="18" y="55" class="small">{unit}</text>']
    for index,(label,value) in enumerate(zip(labels,values)):
        x=160+index*280;height=280*value/maximum;y=365-height
        pieces.append(f'<rect x="{x}" y="{y:.1f}" width="150" height="{height:.1f}" fill="#2563eb"/>')
        pieces.append(f'<text x="{x+75}" y="390" text-anchor="middle" class="small">{label}</text>')
        pieces.append(f'<text x="{x+75}" y="{y-8:.1f}" text-anchor="middle" class="small">{value:.3f}</text>')
    return "".join(pieces)+"</svg>"


def _path_figure() -> str:
    return _svg_start("Fine-grained COW path") + '''
<text x="18" y="35" class="title">Transaction-local COW path</text>
<rect x="40" y="85" width="210" height="70" rx="7" class="box" fill="#e2e8f0"/>
<text x="145" y="115" text-anchor="middle">Committed profile</text><text x="145" y="138" text-anchor="middle" class="small">read-only during transaction</text>
<path d="M250 120 H340" class="arrow"/><rect x="340" y="75" width="250" height="90" rx="7" class="box" fill="#fef3c7"/>
<text x="465" y="107" text-anchor="middle">Copied chain only</text><text x="465" y="132" text-anchor="middle" class="small">profile → authorization</text><text x="465" y="151" text-anchor="middle" class="small">2 copied containers</text>
<path d="M590 120 H680" class="arrow"/><rect x="680" y="85" width="170" height="70" rx="7" class="box" fill="#dcfce7"/>
<text x="765" y="115" text-anchor="middle">external_sharing</text><text x="765" y="138" text-anchor="middle" class="small">false → true</text>
<text x="40" y="220" class="small">Unchanged name and preferences remain shared safely; reads return copies and explicit mutation APIs prevent leakage.</text>
</svg>'''


def _svg_start(title: str) -> str:
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="900" height="430" viewBox="0 0 900 430" role="img" aria-label="{title}"><defs><marker id="a" markerWidth="9" markerHeight="7" refX="8" refY="3.5" orient="auto"><path d="M0 0 L9 3.5 L0 7Z" fill="#334155"/></marker><style>text{{font-family:Arial,sans-serif;fill:#172033;font-size:16px}}.title{{font-size:20px;font-weight:700}}.small{{font-size:13px}}.axis{{stroke:#475569;stroke-width:1.5;fill:none}}.box{{stroke:#334155;stroke-width:1.5}}.arrow{{stroke:#334155;stroke-width:2;fill:none;marker-end:url(#a)}}</style></defs>'''


def _report(summary: dict[str, Any]) -> str:
    lines = ["# Stage 12B measured summary", "", f"Records: {summary['records']}.", "",
             "| Strategy | Outcome | Median total (ms) | Median copy amplification | Integrity | Materialization |",
             "|---|---|---:|---:|---:|---:|"]
    for row in summary["aggregates"]:
        lines.append(
            f"| {row['strategy']} | {row['outcome']} | {row['median_total_ns']/1e6:.6f} | "
            f"{row['median_copy_amplification']:.3f} | {row['rollback_integrity_rate']:.1%} | "
            f"{row['full_materialization_rate']:.1%} |"
        )
    lines += ["", "These are one-iteration, local synthetic measurements. See `limitations.md`."]
    return "\n".join(lines)+"\n"


def _json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True))


def _csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as handle:
        writer=csv.DictWriter(handle,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
