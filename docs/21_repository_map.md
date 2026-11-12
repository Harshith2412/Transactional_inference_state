# Repository map

```text
README.md                  concise entry point
TRUST_BOUNDARY.md          preserved Stage 5 trust note
docs/                      comprehensive documentation freeze
src/transactional_inference_state/
tests/                     deterministic and optional-live tests
evaluation_results/        immutable measured/generated artifacts
```

## Source modules

| File | Purpose / main API | Stage | Kind / dependencies |
|---|---|---:|---|
| `runtime.py` | state, sessions, events, strategies, shared versions, policy, transactions | 1–3 | trusted core; stdlib |
| `experiment.py` | rollback, dirty-read, conflict experiments | 1–2 | experiment over runtime |
| `integrity.py` | canonical JSON and SHA-256 | 3 | trusted integrity helper |
| `benchmark.py` | deterministic state generator, phase/allocation metrics | 3 | benchmark; runtime/integrity |
| `effects.py` | pending effects, fake email, manager, tool proxy | 4 | trusted simulated-effect boundary |
| `effect_experiments.py` | rejected/accepted/concurrent/partial experiments | 4 | experiments |
| `model.py` | adapter protocol, deterministic/Ollama adapters | 5 | untrusted producer boundary; stdlib HTTP |
| `operations.py` | strict plan schema/parser, executor, runner | 5 | trusted parser/executor |
| `model_experiments.py` | benign, poisoning, exfiltration, mixed scenarios | 5 | experiments |
| `evaluation.py` | scenarios, paired harness, outcomes, Stage 6 corpora | 6–7 | evaluation |
| `stage7.py` | expanded corpora, live matrix, statistics, pairing, snapshot matrix | 7 | evaluation/analysis |
| `reporting.py` | exports, tables, plots, research reports | 7 | reporting; matplotlib only for plots |
| `__main__.py` | dependency-light CLI | 7 | orchestration |
| `__init__.py` | public package exports | all | package facade |

## Tests

- `test_runtime.py`: Stage 1 state, rollback, lifecycle, sessions.
- `test_concurrency.py`: isolation, dirty reads, conflicts, concurrent lifecycle.
- `test_snapshot_strategies.py`: full/delta correctness, nesting, digest, benchmarks.
- `test_effects.py`: effect staging, order, ownership, failure.
- `test_model_integration.py`: adapters, strict parser, executor, Stage 5 scenarios;
  contains separately marked optional Ollama test.
- `test_evaluation.py`: Stage 6 scenarios, paired metrics, exports.
- `test_stage7.py`: expanded corpora, taxonomy, statistics, matrix, tables.

Generated artifacts are mapped in [results](14_results.md) and the
[evaluation summary](../evaluation_results/report/evaluation_summary.md).

