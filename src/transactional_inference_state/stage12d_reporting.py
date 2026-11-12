"""Dependency-free Stage 12D measured artifact generation."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def generate_stage12d_artifacts(document: dict[str, Any], output: Path) -> dict[str, Any]:
    for name in ("flagship", "comparison", "validators", "performance",
                 "tables", "figures", "report"):
        (output / name).mkdir(parents=True, exist_ok=True)
    _json(output / "flagship/selective_commit.json", document["flagship"])
    _json(output / "flagship/quarantine_dependency.json", document["quarantine_dependency"])
    _json(output / "flagship/review_required.json", {
        "status": "review_required", "automatic_resolution": False,
        "integrity": "transaction-bound SHA-256 review token",
    })
    _json(output / "comparison/binary_vs_selective.json", document["comparison"])
    rows = []
    for mode in ("binary", "selective"):
        item = document["comparison"][mode]
        rows.append({"mode": mode, **item})
    _csv(output / "comparison/summary.csv", rows)
    _json(output / "validators/raw_results.json", document["validator_disagreement"])
    _json(output / "validators/disagreement_summary.json", document["validator_disagreement"])
    _json(output / "performance/summary.json", document["performance"])
    _csv(output / "tables/table_1_binary_vs_selective.csv", rows)
    _csv(output / "tables/table_2_performance.csv", document["performance"]["rows"])
    _json(output / "report/summary.json", document)
    (output / "report/stage12d_summary.md").write_text(_report(document))
    (output / "report/limitations.md").write_text(
        "# Stage 12D limitations\n\nHandcrafted deterministic validators and explicit lineage; "
        "in-memory quarantine; COW path writes only; no durable review workflow; simulated effects; "
        "no compensation; small local timing samples; semantic dependencies absent from lineage are "
        "not inferred. Selective commit adds complexity and is not claimed inherently safer than rollback.\n"
    )
    _figures(document, output / "figures")
    return document


def _figures(doc: dict[str, Any], output: Path) -> None:
    flagship, comparison = doc["flagship"], doc["comparison"]
    (output / "figure_1_architecture.svg").write_text(_architecture())
    (output / "figure_2_field_outcomes.svg").write_text(_bars(
        "Field outcomes", ["committed", "quarantined", "rejected"],
        [len(flagship["committed_paths"]), len(flagship["quarantined_paths"]),
         flagship["malicious_fields_rejected"]]))
    (output / "figure_3_useful_retention.svg").write_text(_bars(
        "Useful-state retention (%)", ["binary", "selective"],
        [100 * comparison["useful_state_retention_rate"][x] for x in ("binary", "selective")]))
    (output / "figure_4_malicious_persistence.svg").write_text(_bars(
        "Malicious persistence (%)", ["binary", "selective"],
        [100 * comparison["malicious_persistence_rate"][x] for x in ("binary", "selective")]))
    (output / "figure_5_dependency_closure.svg").write_text(_dependency())
    disagreement = doc["validator_disagreement"]
    (output / "figure_6_validator_disagreement.svg").write_text(_bars(
        "Validator disagreement", ["agree", "disagree"],
        [disagreement["trials"] - disagreement["disagreements"], disagreement["disagreements"]]))
    perf = doc["performance"]["rows"]
    (output / "figure_7_selective_latency.svg").write_text(_line(
        "Selective-commit median latency", [str(row["fields"]) for row in perf],
        [row["selective_commit_median_ns"] / 1000 for row in perf]))
    (output / "figure_8_quarantine_distribution.svg").write_text(_bars(
        "Quarantine outcome distribution", ["normal", "quarantine"],
        [len(flagship["committed_paths"]), len(flagship["quarantined_paths"])]))


def _start(title):
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="900" height="440" viewBox="0 0 900 440" role="img" aria-label="{title}"><style>text{{font-family:Arial;fill:#172033;font-size:14px}}.t{{font-size:21px;font-weight:700}}.a{{stroke:#475569;stroke-width:2;fill:none}}</style><text x="25" y="35" class="t">{title}</text>'


def _bars(title, labels, values):
    maximum = max([1, *values]); parts = [_start(title)]
    for index, (label, value) in enumerate(zip(labels, values)):
        x = 100 + index * 700 / max(1, len(labels)); height = 280 * value / maximum
        parts += [f'<rect x="{x}" y="{365-height}" width="100" height="{height}" fill="#2563eb"/>',
                  f'<text x="{x+50}" y="390" text-anchor="middle">{label}</text>',
                  f'<text x="{x+50}" y="{350-height}" text-anchor="middle">{value:.2f}</text>']
    return "".join(parts) + "</svg>"


def _line(title, labels, values):
    maximum = max(values) or 1; parts = [_start(title), '<path d="M80 70 V370 H840" class="a"/>']; points = []
    for index, (label, value) in enumerate(zip(labels, values)):
        x = 100 + index * 700 / max(1, len(labels)-1); y = 360 - 270 * value / maximum
        points.append(f"{x},{y}"); parts += [f'<circle cx="{x}" cy="{y}" r="5" fill="#15803d"/>',
            f'<text x="{x}" y="395" text-anchor="middle">{label} fields</text>',
            f'<text x="{x}" y="{y-12}" text-anchor="middle">{value:.1f} us</text>']
    return "".join(parts) + f'<polyline points="{" ".join(points)}" fill="none" stroke="#15803d" stroke-width="3"/></svg>'


def _architecture():
    return _start("Binary and opt-in selective resolution") + '''<rect x="40" y="100" width="180" height="70" rx="8" fill="#dbeafe" stroke="#334155"/><text x="130" y="140" text-anchor="middle">tentative transaction</text><path d="M220 135 H340" class="a"/><rect x="340" y="90" width="190" height="90" rx="8" fill="#fef3c7" stroke="#334155"/><text x="435" y="125" text-anchor="middle">trusted validator</text><text x="435" y="148" text-anchor="middle">structured decision</text><path d="M530 115 H650" class="a"/><rect x="650" y="75" width="190" height="70" rx="8" fill="#dcfce7" stroke="#334155"/><text x="745" y="115" text-anchor="middle">binary commit/rollback</text><path d="M530 155 H650" class="a"/><rect x="650" y="160" width="190" height="100" rx="8" fill="#ede9fe" stroke="#334155"/><text x="745" y="195" text-anchor="middle">opt-in selective</text><text x="745" y="218" text-anchor="middle">commit / quarantine</text><text x="745" y="241" text-anchor="middle">dependency closure</text></svg>'''


def _dependency():
    return _start("Dependency closure") + '''<rect x="100" y="105" width="150" height="60" fill="#fee2e2" stroke="#334155"/><text x="175" y="140" text-anchor="middle">B quarantined</text><path d="M250 135 H375" class="a"/><rect x="375" y="105" width="150" height="60" fill="#fef3c7" stroke="#334155"/><text x="450" y="140" text-anchor="middle">C depends on B</text><path d="M525 135 H650" class="a"/><rect x="650" y="105" width="150" height="60" fill="#fef3c7" stroke="#334155"/><text x="725" y="140" text-anchor="middle">D depends on C</text><text x="450" y="230" text-anchor="middle">C and D cannot normal-commit</text></svg>'''


def _report(doc):
    f, c = doc["flagship"], doc["comparison"]
    return f'''# Stage 12D measured summary

Flagship: {f["benign_fields_committed"]}/{f["benign_fields_proposed"]} benign fields committed; {f["malicious_fields_committed"]}/{f["malicious_fields_proposed"]} malicious/dependent fields normal-committed; {f["malicious_fields_quarantined"]} quarantined; {f["dependent_fields_correctly_blocked"]} dependent field blocked; {f["external_effect_leakage"]} effects leaked.

Binary useful-state retention was {c["useful_state_retention_rate"]["binary"]:.0%}; selective retention was {c["useful_state_retention_rate"]["selective"]:.0%}. Both observed malicious persistence rates were 0% in one controlled transaction per mode. These denominators are not generalizable.
'''


def _json(path, value): path.write_text(json.dumps(value, indent=2, sort_keys=True))
def _csv(path, rows):
    if not rows: path.write_text(""); return
    fieldnames = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames); writer.writeheader(); writer.writerows(rows)
