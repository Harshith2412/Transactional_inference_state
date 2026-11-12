# Reproducibility

## Two reproducibility levels

Deterministic reproduction covers the test suite, corpus inventory, deterministic
evaluation, and functional snapshot checks. Benchmark timings are repeatable
measurements but hardware dependent. Ollama experiments are experimental
replications: model versions, sampling, host load, and transport can change raw
text and latency, so bit-for-bit live-output reproduction is not claimed.

## Environment and installation

Use Python 3.10 or later. The frozen audit used Python 3.14.3 on arm64 macOS;
earlier development used Python 3.13. The core has no third-party runtime
dependency. From the repository root:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python3.13 -m pip install -e .
python3.13 -m pip install pytest
python3.13 -m pytest -q
```

The historical freeze result is `263 passed, 1 skipped, 0 failed`. After Stage
12E development, the expected current result is `351 passed, 1
skipped, 0 failed`. The skip is the optional Ollama test unless `OLLAMA_MODEL` is
configured.

## Deterministic workflows

The corpus inventory is read-only and quick:

```bash
PYTHONPATH=src python3.13 -m transactional_inference_state evaluate corpus
```

The deterministic Stage 7 security evaluation writes under
`evaluation_results/deterministic_stage7/`:

```bash
PYTHONPATH=src python3.13 -m transactional_inference_state evaluate deterministic
```

The frozen Stage 10 held-out evaluation writes corpus, result, table, and figure
artifacts under `evaluation_results/stage10/`. Running it rewrites those generated
files, so copy the repository or verify hashes afterward when auditing the freeze:

```bash
PYTHONPATH=src python3.13 -m transactional_inference_state evaluate stage10
```

The snapshot benchmark writes `evaluation_results/snapshot_matrix/`. Its workload
is fixed but elapsed time and memory observations depend on the machine:

```bash
PYTHONPATH=src python3.13 -m transactional_inference_state benchmark snapshot-matrix --iterations 7
```

Report regeneration consumes exported Stage 7 and snapshot files. Matplotlib is
optional and required for plots:

```bash
python3.13 -m pip install matplotlib
MPLBACKEND=Agg MPLCONFIGDIR=/tmp/tis-mpl PYTHONPATH=src \
  python3.13 -m transactional_inference_state report plots
```

Tests and corpus inventory normally complete in seconds. The full snapshot matrix
can take minutes and its duration scales with configured sizes and iterations.

## Optional Ollama replication

The frozen live work used Ollama client 0.32.9 and model tags `llama3.2:3b` and
`qwen3:4b`. A running local service and installed model are required:

```bash
ollama pull llama3.2:3b
ollama pull qwen3:4b
OLLAMA_MODEL=llama3.2:3b python3.13 -m pytest -q -m ollama
PYTHONPATH=src python3.13 -m transactional_inference_state evaluate models \
  --models llama3.2:3b qwen3:4b --trials 5 --malicious-limit 20 --benign-limit 20
PYTHONPATH=src python3.13 -m transactional_inference_state evaluate structured-output \
  --models llama3.2:3b qwen3:4b --trials 5
```

Stage 11 report regeneration consumes the preserved Stage 11 summary and does
not make model calls:

```bash
PYTHONPATH=src python3.13 -m transactional_inference_state evaluate stage11
```

Do not run that command in a pristine freeze checkout without first recording
hashes, because it regenerates report artifacts. The original 150-generation
campaign is preserved in `evaluation_results/stage11/live_models/`; its exact
generation driver and frozen manifests are documented in
`docs/30_stage11_live_external_validation.md`.

## Freeze verification

```bash
python3 research_release/verify_freeze.py
PYTHONPATH=src python3.13 research_release/demo.py
```

The verifier checks every SHA-256 entry in the manifest. Evaluation outputs are
under `evaluation_results/`; release analysis is under `research_release/`; the
paper draft is under `paper/`.

## Stage 12A and Stage 12B development checks

The post-freeze provenance and COW stages are deterministic and require no model:

```bash
PYTHONPATH=src python3.13 -c \
  "import transactional_inference_state as t; print(t.run_provenance_experiments())"
PYTHONPATH=src python3.13 -c \
  "import transactional_inference_state as t; print(t.run_flagship_cow_experiment('rollback')); print(t.run_flagship_cow_experiment('commit'))"
PYTHONPATH=src python3.13 -c \
  "import transactional_inference_state as t; print(len(t.run_cow_benchmark(sizes=('10KB',), mutation_ratios=(.01,), depths=(3,), iterations=1)))"
```

The last command is a six-cell smoke matrix covering three strategies and two
outcomes. The preserved full Stage 12B matrix has 216 records under
`evaluation_results/stage12b/benchmark/`. Timing reproduction is local and will
not be bit-for-bit identical.
