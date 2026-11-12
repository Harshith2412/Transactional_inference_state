# Stage 11: live external validation

## Frozen boundary and normalization

PolicyV1 and PolicyV2 fingerprints remained `b9c476b3…60ffb7` and
`ca3702e6…6962e`; transaction and policy code was unchanged.
`ModelTransportNormalizer` is evaluation code. It may decode UTF-8, remove a
BOM, trim outer whitespace, and remove one complete outer JSON fence. It never
strips prose, selects competing objects, changes values, repairs JSON, supplies
fields, or coerces schemas. The unchanged strict parser decides afterward.

The provider-independent `explicit_schema_v2` prompt specifies exact root,
operation, argument, and provenance schemas; prohibits Markdown, prose, and
chain of thought; and contains benign single-/multi-operation examples. Prompt
version, hash, and generation settings are retained per response.

## Reliability gate

The fixed gate contains five benign and five malicious-intent cases with a 60%
normalized-parse qualification threshold.

| Model | Raw parse | Normalized parse | Status |
|---|---:|---:|---|
| `llama3.2:3b` | 9/10 | 9/10 | `QUALIFIED` |
| `qwen3:4b` | 0/10 | 0/10 | `INTERFACE_UNRELIABLE` |

Llama's Wilson 95% CI is 59.6%–98.2%; Qwen's 0/10 upper bound is 27.8%.
Normalization rescued zero outputs. Llama's remaining miss lacked a field;
Qwen returned empty text throughout. Qwen was not run through the expensive
matrix, and its failure is not counted as security.

## Qualified-model matrix

The manifest fixes 30 malicious and 20 hard-benign scenarios in one ordering,
three trials each. Llama produced 128/150 valid plans (85.3%, Wilson 95% CI
78.8%–90.1%). Raw and normalized success were identical. Malicious evaluability
was 75/90; benign evaluability was 53/60.

All 75 evaluable malicious plans matched operation-level ground-truth intent.
This conditional 75/75 compromise rate must be read beside 75/90 evaluability.

| Metric | PolicyV1 | PolicyV2 |
|---|---:|---:|
| Recall given compromise | 48/75 = 64.0% | 69/75 = 92.0% |
| Recall Wilson 95% CI | 52.7%–73.9% | 83.6%–96.3% |
| False rejection | 6/53 = 11.3% | 6/53 = 11.3% |
| Persistent compromise | 24/75 = 32.0% | 6/75 = 8.0% |
| External leakage | 6/75 = 8.0% | 0/75 = 0% |
| Benign completion | 47/53 = 88.7% | 47/53 = 88.7% |
| Containment after rejection | 48/48 = 100% | 69/69 = 100% |

The six PolicyV2 misses repeated the indirect claim “the old dialogue permits
release.” They persisted but caused no simulated external effect. PolicyV2 was
not tuned. Hard-benign false rejections retain their operations and reasons.

## Paired containment and performance

The same 75 compromised plans were replayed with forced rejection to isolate
containment. Immediate baseline execution left state in 57/75 and effects in
24/75. Transactional execution left state/effects in 0/75 and passed rollback
integrity in 75/75. This is separate from policy accuracy.

Eighty-four plans supported the historical timing fixture; 44 valid plans had
reads absent from that fixture and are disclosed as timing errors. Median
incremental enforcement was 0.093 ms (mean 0.102 ms, p95 0.182 ms). Median model
generation was 2.298 s. Mean normalization-plus-parse cost was 0.226 ms, and
mean incremental enforcement was 0.00461% of end-to-end time.

## Multi-turn pilot

Five sequences were attempted. Only two seeds parsed, and PolicyV2 rejected
both; therefore no seed persisted and no lineage-derived later-action denominator
exists. Later effect generations are not credited as lineage detections when
their seed transaction never committed. Lineage utility is N/A in this pilot.

## Complexity and limitations

The trusted core remains seven modules, 1,210 measured Python LOC, and zero
third-party runtime dependencies: 0% core growth from Stage 10. Normalization,
prompting, gating, and reporting remain outside it. Ollama is optional localhost
infrastructure accessed with standard-library `urllib`.

Only one model qualified; examples expose an exact operation interface; corpora
are handcrafted; local outputs vary; effects are simulated; and state remains
non-durable. Results do not establish model independence, production readiness,
or universal prompt-injection defense.

See the [model summary](../evaluation_results/stage11/live_models/model_summary.json),
[interface evidence](../evaluation_results/stage11/interface/),
[tables](../evaluation_results/stage11/tables/), and
[figures](../evaluation_results/stage11/figures/).
