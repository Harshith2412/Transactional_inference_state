# CLI and usage

Invoke with `PYTHONPATH=src python -m transactional_inference_state` when the
package is not installed.

## `evaluate corpus`

Prints Stage 7 malicious/benign totals and counts per family/category. It writes
nothing.

## `evaluate deterministic`

Runs every expanded scenario once in baseline and transactional modes. No
arguments. Writes JSON/CSV/aggregates to
`evaluation_results/deterministic_stage7/` and paired comparisons JSON.

## `evaluate stage8`

Runs the deterministic independent-policy, evasion, semantic, multi-turn,
resource-budget, and failure-injection evaluations. It writes a JSON summary,
eight CSV tables, and ten SVG figures under `evaluation_results/stage8/`.

## `evaluate stage9`

Reproduces PolicyV1, analyzes its Stage 8 false negatives, evaluates frozen
PolicyV2 on separate development and held-out splits, runs six ablations and
hard-benign/multi-turn comparisons, incorporates bounded live results when
present, and writes eight CSV tables plus ten SVG figures under
`evaluation_results/stage9/`.

## `evaluate stage10`

Regenerates the frozen 100/80 deterministic external validation, corpus and live
subset manifests, complexity audit, ten tables, twelve figures, and report files
under `evaluation_results/stage10/`. Existing live-model measurements are
incorporated without rerunning Ollama.

## `evaluate stage11`

Regenerates ten tables, twelve figures, and reports from completed Stage 11 gate
and qualified-model artifacts. Live execution remains separate from pytest and
report regeneration.

## `evaluate models`

```text
evaluate models --models MODEL [MODEL ...]
                [--trials 5] [--malicious-limit 20] [--benign-limit 20]
```

Checks `ollama list`, skips unavailable requested models, uses strict-JSON
prompting, reuses each output for its mode pair, and writes
`evaluation_results/live_models/`.

## `evaluate structured-output`

```text
evaluate structured-output --models MODEL [MODEL ...] [--trials 5]
```

Uses the explicit-schema prompt on fixed limits of five malicious and five
benign scenarios and writes `evaluation_results/structured_output/`.

## `benchmark snapshot-matrix`

```text
benchmark snapshot-matrix [--iterations 7] [--sizes 10KB 100KB 1MB 10MB 50MB]
```

Defaults to all five named sizes and all six fixed mutation ratios. Writes raw
JSON/CSV and summary CSV under `evaluation_results/snapshot_matrix/`. Large
settings are intentionally not part of pytest.

## `report plots`

Reads Stage 7 deterministic raw results and snapshot matrix exports, generates
ten SVG files under `evaluation_results/figures/`, tables/report files under
`evaluation_results/report/`, and prints figure paths. Matplotlib must be
installed. In restricted environments set a writable `MPLCONFIGDIR` and
noninteractive `MPLBACKEND=Agg`.

`LiveEvaluationConfiguration.from_json(path)` is an implemented Python API for
configuration files; the CLI itself currently exposes arguments, not `--config`.
