# Policy and validation

`PolicyValidator` supports a fixed Boolean decision or deterministic callable
over `InferenceState`. A fixed decision can validate a delta transaction without
materializing full state; a callable receives materialized state. Commit is
forbidden before successful validation. Rejected transactions remain open only
for rollback and cannot commit.

The historical Stage 6/7 evaluator retains scenario-encoded `policy_accept` for
reproducibility. Stage 8 adds a separate `PolicyEngine` whose API accepts only
parsed operations and trusted runtime context: capabilities, session/resource
scope, immutable provenance, sensitive aliases, and explicit semantic rules.
It never accepts scenario ground-truth labels.

Four concepts must remain separate:

1. **Model compromise:** the plan matches scenario malicious intent.
2. **Policy detection:** policy rejects that compromised plan.
3. **Runtime containment:** rejected compromise leaves no prohibited state/effect.
4. **End-to-end compromise:** unsafe behavior survives parsing, policy, and runtime.

The Stage 8 60-trial deterministic corpus measured TP=27, FN=13, FP=0, TN=20:
precision 100%, recall 67.5%, and F1 80.6%. A policy false negative commits
malicious tentative state by design; rollback cannot compensate for acceptance.
