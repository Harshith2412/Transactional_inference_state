# Final pre-paper validation

Regression: 351 passed, 1 optional skip, 0 failed. Llama gate: 9/10; full parse: 129/150. Qwen gate: 0/10 empty outputs and interface-unreliable. PolicyV1 recall: 30/72; PolicyV2 recall: 51/72. Forced rejection preserved rollback integrity for 72/72 compromised plans with zero state or effect leakage. Delayed pilot root attribution and recovery: 5/5.

Decision: **MORE_VALIDATION_REQUIRED** because PolicyV2 live recall fell from 69/75 (92.0%) at Stage 11 to 51/72 (70.8%) now, and Qwen remains unevaluable.
