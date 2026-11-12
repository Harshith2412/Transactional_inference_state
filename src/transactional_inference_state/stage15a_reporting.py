"""Artifact writer for the standalone Stage 15A feasibility study."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .stage15a import evaluate_stage15a


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _svg(path: Path, title: str, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(f'<text x="20" y="{55 + index * 28}" font-size="14">{line}</text>'
                   for index, line in enumerate(lines))
    path.write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="900" height="{90 + len(lines)*28}">'
                    f'<text x="20" y="25" font-size="20">{title}</text>{text}</svg>\n')


def generate_stage15a_artifacts(destination: str | Path) -> dict[str, Any]:
    root = Path(destination); result = evaluate_stage15a(root / "services/runtime")
    for folder, key in (("environment", "environment"), ("baseline", "baseline"),
                        ("filesystem", "filesystem"), ("effects", "external_effects"),
                        ("performance", "performance"), ("comparison", "backends")):
        _write_json(root / folder / "results.json", result[key])
    for backend in ("criu", "dmtcp"):
        probe = next(item for item in result["backends"] if item["backend"].lower() == backend)
        _write_json(root / backend / "results.json", {"probe": probe, "experiments": [],
            "finding": "native experiment not run on unsupported host"})
    _write_json(root / "services" / "state_models.json", {
        "tool_initial": result["baseline"]["initial"]["tool"],
        "rag_initial": result["baseline"]["initial"]["rag"]})
    _write_json(root / "report" / "stage15a_results.json", result)
    tables = {
        "01_environment.json": result["environment"], "02_backend_availability.json": result["backends"],
        "03_baseline.json": result["baseline"], "04_state_integrity_oracle.json": result["oracle"],
        "05_filesystem_and_external_effects.json": {"filesystem": result["filesystem"], "effects": result["external_effects"]},
        "06_performance_matrix.json": result["performance"], "07_failure_injection.json": result["failure_injection"],
        "08_criu_vs_dmtcp.json": result["backends"], "09_boundary_levels.json": result["boundary_levels"],
        "10_integration_suitability.json": result["recommendation"]}
    for name, value in tables.items(): _write_json(root / "tables" / name, value)
    _svg(root / "figures" / "01_checkpoint_boundary.svg", "External process checkpoint boundary",
         ["S0 → checkpoint → mutation S1 → reject → restore S0", "Unmanaged effects remain outside the boundary"])
    _svg(root / "figures" / "02_backend_availability.svg", "Native backend availability",
         [f"{x['backend']}: {x['status']}" for x in result["backends"]])
    _svg(root / "figures" / "03_side_effect_boundary.svg", "Negative side-effect result",
         ["Service memory: restorable in oracle", "Observer/file mutation: remains"])
    _svg(root / "figures" / "04_transaction_levels.svg", "Future transaction boundary levels",
         list(result["boundary_levels"].values()))
    summary = """# Stage 15A Summary

This host is macOS arm64. Native CRIU and DMTCP checkpoint/restore was not run,
and no success is claimed. Deterministic application baselines confirm that
external-process mutation persists without a checkpoint. A CI-only in-memory
oracle validates state models, canonical digests, structural comparisons, and
the flagship transcript, but is explicitly not counted as a checkpoint backend.

The negative boundary tests show that restoring service memory does not restore
a separate observer record or filesystem mutation. Stage 15B integration is not
justified from this host's measurements; the prepared Linux runners must first
produce successful native integrity, socket, failure, and performance results.
"""
    (root / "report" / "stage15a_summary.md").write_text(summary)
    (root / "report" / "feasibility.md").write_text("# Feasibility\n\nCRIU: UNAVAILABLE. DMTCP: UNAVAILABLE. Native Linux measurements required before integration.\n")
    (root / "report" / "limitations.md").write_text("""# Limitations

- macOS cannot natively execute CRIU or DMTCP.
- CI oracle restore is not process checkpoint evidence.
- Socket survival, PID behavior, image size, latency, and repeated cycles remain unmeasured.
- Process restore does not imply filesystem, remote API, email, banking, or unmanaged-service rollback.
- Coordinated multi-process atomicity was not demonstrated.
""")
    (root / "report" / "flagship_transcript.txt").write_text(result["transcript"] + "\n")
    return result
