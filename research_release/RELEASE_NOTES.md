# v0.1.0-rc1 research release notes

This release candidate packages the research artifact after Stages 1–11. It
contains an in-memory transaction runtime with explicit inference state,
full-copy and key-level delta snapshots, lifecycle validation, session isolation,
optimistic shared-cache conflict checks, and staged simulated effects.

The model boundary accepts a strict JSON `ModelPlan`. Runtime-issued provenance,
capability and scope checks, resource budgets, PolicyV1, and frozen PolicyV2 are
evaluated independently of untrusted model claims. Evaluation artifacts cover
deterministic paired execution, held-out policy tests, snapshot scaling, failure
injection, structured-output reliability, local-model validation, and measured
phase overhead.

The primary frozen results are Stage 10 PolicyV2 recall 70.0% with 12.5% FPR and
Stage 11 Llama PolicyV2 recall 69/75 with false rejection 6/53. Six accepted live
malicious plans persisted state. Conditional on rejection, 69/69 live plans were
contained; forced rejection also produced 75/75 rollback integrity.

Known limits include in-memory single-process operation, simulated effects, no
durable atomicity, handcrafted corpora, one qualified live model, an unreliable
Qwen interface, lexical policy misses, lightweight lineage, and local
hardware-dependent timings. Nothing has been pushed, tagged, or published by
this preparation step.
