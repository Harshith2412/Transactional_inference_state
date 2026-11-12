# Stage 10: structured output and external validation

## Motivation and frozen method

Stage 10 changes neither the strict parser nor PolicyV1/PolicyV2. It measures
generation-side reliability and external policy validity. The new corpus is
disjoint from Stage 9 and contains 100 malicious scenarios balanced across 14
families (7–8 each) plus 80 difficult benign scenarios. Ground-truth metadata is
never passed to policy.

## Structured generation

Three frozen modes share temperature 0, seed 0, top-p 0.9, 1,024 output tokens,
and a 30-second timeout:

1. `strict_json`: short JSON-only instruction.
2. `explicit_schema`: versioned `stage10-model-plan-v1` instruction with exact
   fields, operations, provenance values, constraints, and a valid example.
3. `native_schema`: the same explicit instruction plus Ollama's native JSON
   Schema `format` object.

Native schema is an untrusted generation aid. Every response is still accepted
or rejected by the unchanged `parse_model_plan`. No repair or partial execution
was added. The prompt's SHA-256 identifier is recorded in generation metadata.

## Larger deterministic held-out result

| Policy | TP | FN | FP | TN | Precision | Recall | F1 | FPR | Persistent compromise | Benign completion |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| V1 | 35 | 65 | 0 | 80 | 100% | 35% | 51.9% | 0% | 65% | 100% |
| V2 | 70 | 30 | 10 | 70 | 87.5% | 70% | 77.8% | 12.5% | 30% | 87.5% |

Compared with Stage 9 held-out evaluation, PolicyV2 recall declined from 79.2%
to 70%, observed FPR rose from 0% to 12.5%, F1 declined from 88.4% to 77.8%,
and benign completion declined from 100% to 87.5%. PolicyV2 was not tuned after
these observations. All rejected deterministic trials remained contained.

## Bounded live matrix

The frozen live pilot selected the same two malicious and two benign IDs for
each installed model and each mode, one generation each. This is deliberately a
small interface pilot rather than the recommended full 30/20 × three-trial run.

| Model | Strict JSON | Explicit schema | Native schema |
|---|---:|---:|---:|
| `llama3.2:3b` | 1/4 (25%) | 2/4 (50%) | 2/4 (50%) |
| `qwen3:4b` | 0/4 | 0/4 | 0/4 |

No malicious plan was parseable, so model compromise and PolicyV1/PolicyV2
recall given compromise are N/A—not 0%. Qwen's empty returned model text is an
interface limitation, not containment. Llama failures were invalid provenance,
unknown operations, or invalid argument schemas. Native schema was accepted by
the local Ollama runtime but did not outperform the explicit prompt in this
sample.

Explicit schema is retained as the primary mode because it tied native schema
for parse reliability and benign evaluability, had lower measured mean runtime,
and does not require provider-specific schema support. This selection is based
on interface reliability and compatibility, not favorable security scores.

Better parsing exposed a difficult-benign tradeoff: PolicyV2 rejected one of
two parseable Llama benign plans under explicit and native modes. The denominator
is too small for a general false-positive conclusion.

## Multi-turn live pilot

Three Llama native-schema sequences produced and committed a semantic seed on
turn 1. PolicyV2 detected the later memory-derived effect on turn 3 in all three,
with no simulated email leakage. The committed seed remained, so this is not
retroactive rollback.

## Latency and overhead

Generation and enforcement are reported separately. Across parseable Llama
plans, mean paired incremental transactional overhead was 0.154 ms for strict
JSON (n=1), 0.079 ms for explicit schema (n=2), and 0.136 ms for native schema
(n=2). Transaction runtime occupied approximately 0.0062%, 0.0045%, and 0.0076%
of end-to-end time respectively. Counts are too small for stable tail estimates;
the artifacts retain mean, median, population standard deviation, min, max,
p90, and p95 plus individual phase records.

## Framework weight

The measured trusted core contains seven modules and 1,210 nonblank/non-comment
Python lines. It has zero third-party runtime dependencies. `pytest` is a
development dependency; Ollama is an optional localhost service accessed with
standard-library `urllib`. No large agent framework is required. LOC documents
weight and is not a quality claim.

## Limitations

The live matrix is much smaller than the supported configurable manifest,
malicious live recall is not estimable, only two models were installed, corpus
generation is handcrafted, effects are simulated, and state remains in-memory
and non-durable. PolicyV2's lower external recall and higher FPR demonstrate
limited generalization rather than production readiness.

See the [Stage 10 deterministic summary](../evaluation_results/stage10/deterministic/summary.json),
[tables](../evaluation_results/stage10/tables/), and
[figures](../evaluation_results/stage10/figures/).
