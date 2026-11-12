# Research freeze notes

This directory records the Stage 12 research freeze for release candidate
`v0.1.0-rc1`, prepared on 2026-08-19. The freeze fixes the Stage 10 corpora,
Stage 11 manifests and measurements, PolicyV1 and PolicyV2, transaction
semantics, and the seven-module trusted core as the evidence base for the paper.

Stage 12 adds documentation, analysis, a paper diagram, a demonstration wrapper,
and a manuscript. It does not retune either policy or modify evaluation data.
SHA-256 digests in `FREEZE_MANIFEST.json` make accidental changes to the central
inputs and results detectable. Live model output is retained as observed, not
presented as bit-for-bit reproducible.

The key interpretation is conditional: rollback and effect discard were reliable
when the policy rejected a transaction in the tested model. Policy detection was
not complete. PolicyV2 missed 30 of 100 deterministic held-out attacks and six of
75 evaluable compromised live plans.
