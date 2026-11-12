# Stage 7 evaluation summary

## Experiment configuration

`{"corpus_version": "stage7-v1", "deterministic_trials": 376, "live_explicit_schema_trials": 200, "live_strict_trials": 800, "ollama_version": "0.32.9", "snapshot_cells": 120}`

Models: deterministic, llama3.2:3b, qwen3:4b. Raw execution records: 1376. Malicious scenarios represented: 112. Benign scenarios represented: 76. Snapshot matrix cells: 120.

## Security and benign utility results

```json
[
  {
    "benign_completion": {
      "count": 76,
      "rate": 1.0,
      "total": 76,
      "wilson_high": 1.0,
      "wilson_low": 0.9518864149348628
    },
    "benign_false_rejection": {
      "count": 0,
      "rate": 0.0,
      "total": 76,
      "wilson_high": 0.048113585065137326,
      "wilson_low": 0.0
    },
    "benign_trials": 76,
    "containment_given_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 80,
      "wilson_high": 0.0458181295355271,
      "wilson_low": 0.0
    },
    "cross_session_violation": {
      "count": 0,
      "rate": 0.0,
      "total": 112,
      "wilson_high": 0.033161347066943875,
      "wilson_low": 3.469446951953614e-18
    },
    "external_leakage": {
      "count": 24,
      "rate": 0.21428571428571427,
      "total": 112,
      "wilson_high": 0.29908008621248594,
      "wilson_low": 0.14844068354005338
    },
    "malicious_trials": 112,
    "mode": "baseline",
    "model": "deterministic",
    "model_compromise": {
      "count": 80,
      "rate": 0.7142857142857143,
      "total": 112,
      "wilson_high": 0.7897516020091828,
      "wilson_low": 0.6246078206764127
    },
    "parse_success": {
      "count": 156,
      "rate": 0.8297872340425532,
      "total": 188,
      "wilson_high": 0.8767729420669976,
      "wilson_low": 0.7695941193714655
    },
    "persistent_compromise": {
      "count": 72,
      "rate": 0.6428571428571429,
      "total": 112,
      "wilson_high": 0.7255041135177758,
      "wilson_low": 0.5507355016059547
    },
    "persistent_given_compromise": {
      "count": 72,
      "rate": 0.9,
      "total": 80,
      "wilson_high": 0.9484523844326191,
      "wilson_low": 0.8148931119389591
    },
    "provenance_spoof_acceptance": {
      "count": 0,
      "rate": 0.0,
      "total": 8,
      "wilson_high": 0.32440756488388023,
      "wilson_low": 0.0
    },
    "rollback_integrity": {
      "count": 0,
      "rate": 0.0,
      "total": 0,
      "wilson_high": 0.0,
      "wilson_low": 0.0
    },
    "total_latency": {
      "count": 188,
      "maximum": 249292,
      "mean": 56052.505319148935,
      "median": 50916.5,
      "minimum": 37708,
      "p90": 66404.3,
      "p95": 70748.25,
      "stdev": 27055.436957134163
    },
    "unavailable_trials": 0
  },
  {
    "benign_completion": {
      "count": 76,
      "rate": 1.0,
      "total": 76,
      "wilson_high": 1.0,
      "wilson_low": 0.9518864149348628
    },
    "benign_false_rejection": {
      "count": 0,
      "rate": 0.0,
      "total": 76,
      "wilson_high": 0.048113585065137326,
      "wilson_low": 0.0
    },
    "benign_trials": 76,
    "containment_given_compromise": {
      "count": 80,
      "rate": 1.0,
      "total": 80,
      "wilson_high": 0.9999999999999999,
      "wilson_low": 0.9541818704644728
    },
    "cross_session_violation": {
      "count": 0,
      "rate": 0.0,
      "total": 112,
      "wilson_high": 0.033161347066943875,
      "wilson_low": 3.469446951953614e-18
    },
    "external_leakage": {
      "count": 0,
      "rate": 0.0,
      "total": 112,
      "wilson_high": 0.033161347066943875,
      "wilson_low": 3.469446951953614e-18
    },
    "malicious_trials": 112,
    "mode": "transactional",
    "model": "deterministic",
    "model_compromise": {
      "count": 80,
      "rate": 0.7142857142857143,
      "total": 112,
      "wilson_high": 0.7897516020091828,
      "wilson_low": 0.6246078206764127
    },
    "parse_success": {
      "count": 156,
      "rate": 0.8297872340425532,
      "total": 188,
      "wilson_high": 0.8767729420669976,
      "wilson_low": 0.7695941193714655
    },
    "persistent_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 112,
      "wilson_high": 0.033161347066943875,
      "wilson_low": 3.469446951953614e-18
    },
    "persistent_given_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 80,
      "wilson_high": 0.0458181295355271,
      "wilson_low": 0.0
    },
    "provenance_spoof_acceptance": {
      "count": 0,
      "rate": 0.0,
      "total": 8,
      "wilson_high": 0.32440756488388023,
      "wilson_low": 0.0
    },
    "rollback_integrity": {
      "count": 112,
      "rate": 1.0,
      "total": 112,
      "wilson_high": 1.0,
      "wilson_low": 0.9668386529330562
    },
    "total_latency": {
      "count": 188,
      "maximum": 1304500,
      "mean": 111327.34042553192,
      "median": 95833.0,
      "minimum": 74125,
      "p90": 145862.5,
      "p95": 156206.15000000002,
      "stdev": 93885.78919170923
    },
    "unavailable_trials": 0
  },
  {
    "benign_completion": {
      "count": 26,
      "rate": 0.20967741935483872,
      "total": 124,
      "wilson_high": 0.28950356458109167,
      "wilson_low": 0.14729885722962444
    },
    "benign_false_rejection": {
      "count": 98,
      "rate": 0.7903225806451613,
      "total": 124,
      "wilson_high": 0.8527011427703756,
      "wilson_low": 0.7104964354189084
    },
    "benign_trials": 124,
    "containment_given_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 24,
      "wilson_high": 0.13797620467498017,
      "wilson_low": 1.3877787807814457e-17
    },
    "cross_session_violation": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "external_leakage": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "malicious_trials": 125,
    "mode": "baseline",
    "model": "llama3.2:3b",
    "model_compromise": {
      "count": 24,
      "rate": 0.192,
      "total": 125,
      "wilson_high": 0.26981091262169365,
      "wilson_low": 0.13255536990263544
    },
    "parse_success": {
      "count": 71,
      "rate": 0.285140562248996,
      "total": 249,
      "wilson_high": 0.3441504375744844,
      "wilson_low": 0.2326594712946126
    },
    "persistent_compromise": {
      "count": 24,
      "rate": 0.192,
      "total": 125,
      "wilson_high": 0.26981091262169365,
      "wilson_low": 0.13255536990263544
    },
    "persistent_given_compromise": {
      "count": 24,
      "rate": 1.0,
      "total": 24,
      "wilson_high": 1.0,
      "wilson_low": 0.8620237953250198
    },
    "provenance_spoof_acceptance": {
      "count": 0,
      "rate": 0.0,
      "total": 0,
      "wilson_high": 0.0,
      "wilson_low": 0.0
    },
    "rollback_integrity": {
      "count": 0,
      "rate": 0.0,
      "total": 0,
      "wilson_high": 0.0,
      "wilson_low": 0.0
    },
    "total_latency": {
      "count": 249,
      "maximum": 6492093500,
      "mean": 1493630085.1927712,
      "median": 1436884292,
      "minimum": 502385167,
      "p90": 2278136875.7999997,
      "p95": 2764703742.2,
      "stdev": 801914903.9153358
    },
    "unavailable_trials": 1
  },
  {
    "benign_completion": {
      "count": 26,
      "rate": 0.20967741935483872,
      "total": 124,
      "wilson_high": 0.28950356458109167,
      "wilson_low": 0.14729885722962444
    },
    "benign_false_rejection": {
      "count": 98,
      "rate": 0.7903225806451613,
      "total": 124,
      "wilson_high": 0.8527011427703756,
      "wilson_low": 0.7104964354189084
    },
    "benign_trials": 124,
    "containment_given_compromise": {
      "count": 24,
      "rate": 1.0,
      "total": 24,
      "wilson_high": 1.0,
      "wilson_low": 0.8620237953250198
    },
    "cross_session_violation": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "external_leakage": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "malicious_trials": 125,
    "mode": "transactional",
    "model": "llama3.2:3b",
    "model_compromise": {
      "count": 24,
      "rate": 0.192,
      "total": 125,
      "wilson_high": 0.26981091262169365,
      "wilson_low": 0.13255536990263544
    },
    "parse_success": {
      "count": 71,
      "rate": 0.285140562248996,
      "total": 249,
      "wilson_high": 0.3441504375744844,
      "wilson_low": 0.2326594712946126
    },
    "persistent_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "persistent_given_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 24,
      "wilson_high": 0.13797620467498017,
      "wilson_low": 1.3877787807814457e-17
    },
    "provenance_spoof_acceptance": {
      "count": 0,
      "rate": 0.0,
      "total": 0,
      "wilson_high": 0.0,
      "wilson_low": 0.0
    },
    "rollback_integrity": {
      "count": 125,
      "rate": 1.0,
      "total": 125,
      "wilson_high": 1.0,
      "wilson_low": 0.9701846062916737
    },
    "total_latency": {
      "count": 249,
      "maximum": 6491978417,
      "mean": 1493605638.9196787,
      "median": 1436858000,
      "minimum": 502362875,
      "p90": 2278108326.0,
      "p95": 2764702449.3999996,
      "stdev": 801886407.5384334
    },
    "unavailable_trials": 1
  },
  {
    "benign_completion": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "benign_false_rejection": {
      "count": 125,
      "rate": 1.0,
      "total": 125,
      "wilson_high": 1.0,
      "wilson_low": 0.9701846062916737
    },
    "benign_trials": 125,
    "containment_given_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 0,
      "wilson_high": 0.0,
      "wilson_low": 0.0
    },
    "cross_session_violation": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "external_leakage": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "malicious_trials": 125,
    "mode": "baseline",
    "model": "qwen3:4b",
    "model_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "parse_success": {
      "count": 0,
      "rate": 0.0,
      "total": 250,
      "wilson_high": 0.015133299495444574,
      "wilson_low": 8.673617379884035e-19
    },
    "persistent_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "persistent_given_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 0,
      "wilson_high": 0.0,
      "wilson_low": 0.0
    },
    "provenance_spoof_acceptance": {
      "count": 0,
      "rate": 0.0,
      "total": 0,
      "wilson_high": 0.0,
      "wilson_low": 0.0
    },
    "rollback_integrity": {
      "count": 0,
      "rate": 0.0,
      "total": 0,
      "wilson_high": 0.0,
      "wilson_low": 0.0
    },
    "total_latency": {
      "count": 250,
      "maximum": 9549004500,
      "mean": 3355881346.996,
      "median": 3337663041.5,
      "minimum": 1062795000,
      "p90": 3971548750.7,
      "p95": 4542641210.3,
      "stdev": 918362915.5306787
    },
    "unavailable_trials": 0
  },
  {
    "benign_completion": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "benign_false_rejection": {
      "count": 125,
      "rate": 1.0,
      "total": 125,
      "wilson_high": 1.0,
      "wilson_low": 0.9701846062916737
    },
    "benign_trials": 125,
    "containment_given_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 0,
      "wilson_high": 0.0,
      "wilson_low": 0.0
    },
    "cross_session_violation": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "external_leakage": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "malicious_trials": 125,
    "mode": "transactional",
    "model": "qwen3:4b",
    "model_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "parse_success": {
      "count": 0,
      "rate": 0.0,
      "total": 250,
      "wilson_high": 0.015133299495444574,
      "wilson_low": 8.673617379884035e-19
    },
    "persistent_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 125,
      "wilson_high": 0.029815393708326456,
      "wilson_low": 1.734723475976807e-18
    },
    "persistent_given_compromise": {
      "count": 0,
      "rate": 0.0,
      "total": 0,
      "wilson_high": 0.0,
      "wilson_low": 0.0
    },
    "provenance_spoof_acceptance": {
      "count": 0,
      "rate": 0.0,
      "total": 0,
      "wilson_high": 0.0,
      "wilson_low": 0.0
    },
    "rollback_integrity": {
      "count": 125,
      "rate": 1.0,
      "total": 125,
      "wilson_high": 1.0,
      "wilson_low": 0.9701846062916737
    },
    "total_latency": {
      "count": 250,
      "maximum": 9548990958,
      "mean": 3355833467.232,
      "median": 3337652208.0,
      "minimum": 1062750083,
      "p90": 3971511116.7,
      "p95": 4542445752.6,
      "stdev": 918354979.2239792
    },
    "unavailable_trials": 0
  }
]
```

## Structured-output reliability

```json
[
  {
    "benign_completion_rate": 1.0,
    "duplicate_operation_id_count": 2,
    "duplicate_operation_id_rate": 0.005319148936170213,
    "extra_field_rate": 0.0,
    "invalid_type_count": 2,
    "invalid_type_rate": 0.005319148936170213,
    "malformed_output_count": 4,
    "malformed_output_rate": 0.010638297872340425,
    "missing_field_count": 2,
    "missing_field_rate": 0.005319148936170213,
    "model": "deterministic",
    "other_parse_failure_count": 18,
    "parse_failure_rate": 0.1702127659574468,
    "parse_success_rate": 0.8297872340425532,
    "prompt_configuration": "strict_json",
    "trials": 376,
    "unavailable_trials": 0,
    "unknown_operation_count": 36,
    "unknown_operation_rate": 0.09574468085106383,
    "valid_schema_policy_rejection_rate": 0.425531914893617
  },
  {
    "benign_completion_rate": 1.0,
    "duplicate_operation_id_rate": 0.0,
    "extra_field_count": 4,
    "extra_field_rate": 0.04,
    "invalid_type_rate": 0.0,
    "malformed_output_rate": 0.0,
    "missing_field_rate": 0.0,
    "model": "llama3.2:3b",
    "parse_failure_rate": 0.04,
    "parse_success_rate": 0.96,
    "prompt_configuration": "explicit_schema",
    "trials": 100,
    "unavailable_trials": 0,
    "unknown_operation_rate": 0.0,
    "valid_schema_policy_rejection_rate": 0.46
  },
  {
    "benign_completion_rate": 0.010101010101010102,
    "duplicate_operation_id_rate": 0.0,
    "extra_field_count": 34,
    "extra_field_rate": 0.08542713567839195,
    "invalid_type_rate": 0.0,
    "malformed_output_count": 2,
    "malformed_output_rate": 0.005025125628140704,
    "missing_field_count": 56,
    "missing_field_rate": 0.1407035175879397,
    "model": "llama3.2:3b",
    "other_parse_failure_count": 258,
    "parse_failure_rate": 0.8844221105527639,
    "parse_success_rate": 0.11557788944723618,
    "prompt_configuration": "strict_json",
    "trials": 398,
    "unavailable_trials": 2,
    "unknown_operation_count": 2,
    "unknown_operation_rate": 0.005025125628140704,
    "valid_schema_policy_rejection_rate": 0.11055276381909548
  },
  {
    "benign_completion_rate": 0.0,
    "duplicate_operation_id_rate": 0.0,
    "extra_field_rate": 0.0,
    "invalid_type_rate": 0.0,
    "malformed_output_count": 100,
    "malformed_output_rate": 1.0,
    "missing_field_rate": 0.0,
    "model": "qwen3:4b",
    "parse_failure_rate": 1.0,
    "parse_success_rate": 0.0,
    "prompt_configuration": "explicit_schema",
    "trials": 100,
    "unavailable_trials": 0,
    "unknown_operation_rate": 0.0,
    "valid_schema_policy_rejection_rate": 0.0
  },
  {
    "benign_completion_rate": 0.0,
    "duplicate_operation_id_rate": 0.0,
    "extra_field_rate": 0.0,
    "invalid_type_rate": 0.0,
    "malformed_output_count": 400,
    "malformed_output_rate": 1.0,
    "missing_field_rate": 0.0,
    "model": "qwen3:4b",
    "parse_failure_rate": 1.0,
    "parse_success_rate": 0.0,
    "prompt_configuration": "strict_json",
    "trials": 400,
    "unavailable_trials": 0,
    "unknown_operation_rate": 0.0,
    "valid_schema_policy_rejection_rate": 0.0
  }
]
```

## Performance and snapshot results

Latency distributions are included in each grouped result above. Snapshot raw phase timings, traced Python allocation, integrity, and crossover analysis are stored under `evaluation_results/snapshot_matrix/`.

## Interpretation boundary

These are measured observations for this corpus, configuration, local models, and environment. Model refusal and parser rejection are not counted as runtime containment. See `limitations.md`.
