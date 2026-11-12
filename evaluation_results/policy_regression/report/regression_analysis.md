# Pre-paper policy regression analysis

## Plain answer

PolicyV2 did not become worse because transaction/runtime semantics changed. For every saved valid input, current frozen PolicyV1 and PolicyV2 exactly reproduce the recorded decisions (zero mismatches across 128 Stage 11 and 129 final plans). The final run supplied materially different model outputs and plans. Why those historical generations diverged cannot be fully identified because Stage 11 did not preserve the full rendered prompt, model digest, or complete per-row generation/runtime context.

## Evidence preservation and alignment

The runs contain the same 50 scenarios in the same order, the same three trials per scenario, the same attack-family counts, and the same 90 malicious/60 benign split. All 150 scenario/trial keys match. Raw alignment is {'SAME_RAW_OUTPUT': 49, 'DIFFERENT_RAW_OUTPUT': 72, 'ONE_SIDE_PARSE_FAILURE': 29}. Structural plan alignment is {'EXACT_PLAN_MATCH': 48, 'DIFFERENT_OPERATION_SEQUENCE': 66, 'ONE_SIDE_PARSE_FAILURE': 29, 'BOTH_PARSE_FAILURE': 7}. Missing historical fields are explicitly listed in `artifact_manifest.json`; no missing field is represented as directly saved.

## Reproduced metrics

Both Stage 11 and final recomputations match their published JSON summaries exactly: True and True. Stage 11 PolicyV2 is 69/75 (92.0%); final is 51/72 (70.8%). The final misses comprise {'SEMANTIC_MEMORY_POISONING': 9, 'INDIRECT_AUTHORIZATION': 6, 'PROVENANCE_CONTEXT': 6}. All nine final false positives triggered the saved `SEMANTIC_POISONING` reason.

The final taxonomy's 63 `POLICY_FALSE_NEGATIVE` entries are policy-decision counts: PolicyV1 contributes 42 and PolicyV2 contributes 21. This is not duplicate counting within either policy. Its nine `POLICY_FALSE_POSITIVE` entries are exactly PolicyV2's nine false rejections; PolicyV1 contributes zero.

## Conditional generation behavior

The controlled 10-malicious/10-benign experiment produced 100 generations, with 90 parse successes. Each scenario's five seed-0 repetitions was byte-identical and structurally identical. Same-seed testing yielded 1 unique raw output; seeds 0–4 yielded 1. The current first repetition matches final validation byte-for-byte for 20/20 subset scenarios, versus 7/20 for Stage 11. This shows no current within-configuration randomness and reproduces the final-generation behavior, but does not identify the cause of the historical cross-run divergence.

## Sampling assessment

The descriptive 10,000-resample bootstrap estimates Stage 11 recall [0.8533333333333334, 0.9733333333333334] and final recall [0.5972222222222222, 0.8055555555555556]; the final-minus-Stage-11 difference interval is [-0.33499999999999996, -0.0888888888888889]. This does not support ordinary plan-level sampling variability as a sufficient explanation and is not presented as a formal significance test.

## Root-cause classification

- **GENERATION_VARIANCE — SUPPORTED:** 101/150 matched trials had different raw text or one-sided parsing; only 48 exact plan matches
- **SCENARIO_DISTRIBUTION_DIFFERENCE — REJECTED:** same 50 scenarios, order, 3 trials each, family counts, and 90/60 split
- **POLICY_CONTEXT_CHANGE — NOT OBSERVED:** current replay matched all 128 Stage 11 and 129 final saved decisions
- **EVALUATION_HARNESS_DIFFERENCE — UNRESOLVED:** timeout changed 30s to 45s without timeouts; Stage 11 full rendered prompts were not saved
- **SAMPLING_VARIANCE — INSUFFICIENT EXPLANATION:** bootstrap difference interval excludes zero in 10,000 descriptive resamples
- **POLICY_REPLAY_BUG — REJECTED:** zero PolicyV1 or PolicyV2 replay mismatches in either run
- **UNKNOWN — SUPPORTED FOR ORIGIN:** historical model digest/full prompt/runtime state were not preserved, so why generations diverged is not identifiable

## Limitations

- Full Stage 11 rendered prompts, model binary/digest, model-load state, and complete per-row policy context were not saved.
- Structural comparison is authoritative; no automatic semantic equivalence is claimed.
- The bootstrap treats evaluable plans independently and is descriptive.
- The controlled subset has 20 scenarios and one currently installed local model version.
- Live recall is conditional on model compromise and parser success, so changing generated forms changes denominators as well as policy decisions.

No policy, parser, normalizer, transaction, provenance, COW, flow, selective-commit, lineage, or paper content was modified.
