# Evaluation methodology

The harness executes deterministic `EvaluationScenario` definitions in paired
baseline and transactional modes. Both use the same structured schema, parser,
scenario, model output, and policy. Baseline applies parsed operations
immediately and validates afterward; transactional mode keeps them local/staged
until validation. This isolates transactional visibility while retaining other
boundaries where practical.

## Stage 6 corpus

Stage 6 used 20 malicious scenarios across 10 families and seven benign
categories, producing 54 mode records. Those artifacts remain at the root of
[`evaluation_results/`](../evaluation_results/).

## Stage 7 deterministic corpus

- 112 malicious scenarios, 14 families, 8 variations each
- 76 benign scenarios, 19 categories, 4 variations each
- 188 scenarios × 2 modes = 376 records

Variations cover wording, placement, source, ordering, operation count, and
session metadata. The corpus is systematic but handcrafted and non-comprehensive.

## Live model design

Installed models were `llama3.2:3b` and `qwen3:4b` under Ollama 0.32.9. The
strict-JSON run used 20 malicious plus 20 benign scenarios, five trials per
model: 400 generations and 800 paired execution records. Each generated raw
response was reused for its baseline/transactional pair. One generation timeout
created two paired `MODEL_UNAVAILABLE` records; they remain raw but are excluded
from security/reliability denominators.

The explicit-schema reliability subset used five malicious and five benign
scenarios, five trials, and both models (100 generations, 200 mode records).
Grammar-constrained generation was not implemented.

## Snapshot matrix

FullCopy and Delta ran commit/rollback across 10 KB, 100 KB, 1 MB, 10 MB, and
50 MB; mutation ratios 1%, 5%, 10%, 25%, 50%, and 100%; seven iterations each.
This yields 120 aggregate cells and 840 measured transactions.

Raw records precede aggregation. Timing uses `perf_counter_ns`; allocation uses
`tracemalloc`, not RSS. See [reproducibility](19_reproducibility.md).

