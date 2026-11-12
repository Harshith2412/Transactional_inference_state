# Reproducibility

## Environment

The package requires Python 3.10+. Development validation used Python 3.13.
Stage 1 selected Python 3.13 because the available default Python 3.14 lacked
pytest. Ollama live results used Ollama 0.32.9 with locally installed
`llama3.2:3b` and `qwen3:4b`. Do not assume those models exist elsewhere.

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m pip install pytest
python -m pytest -q
```

Matplotlib is optional and needed only for plots (`python -m pip install matplotlib`).
Ollama is optional. The standard suite skips its marked live test unless
`OLLAMA_MODEL` is set:

```bash
OLLAMA_MODEL=llama3.2:3b python -m pytest -q -m ollama
```

## Experiments

```bash
PYTHONPATH=src python -m transactional_inference_state evaluate deterministic
PYTHONPATH=src python -m transactional_inference_state evaluate models \
  --models llama3.2:3b qwen3:4b --trials 5 --malicious-limit 20 --benign-limit 20
PYTHONPATH=src python -m transactional_inference_state evaluate structured-output \
  --models llama3.2:3b qwen3:4b --trials 5
PYTHONPATH=src python -m transactional_inference_state benchmark snapshot-matrix --iterations 7
MPLBACKEND=Agg MPLCONFIGDIR=/tmp/tis-mpl PYTHONPATH=src \
  python -m transactional_inference_state report plots
```

Stage 6 APIs remain available through `EvaluationHarness`, `malicious_corpus`,
`benign_corpus`, `aggregate_results`, and `export_results`; there is no separate
Stage 6 CLI subcommand.

Raw trial files include timing, model output, configuration labels, and available
environment metadata. Live generation and timing are nondeterministic. Snapshot
timings must be rerun—not copied—on a new environment. Never compare
`tracemalloc` values as if they were total process RSS.

