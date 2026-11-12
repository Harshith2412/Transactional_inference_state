# Paper-readiness analysis

1. **Regression:** yes—351 passed, 1 optional Ollama skip, 0 failed; historical hashes and policy fingerprints matched.
2. **Llama usability:** yes—gate 9/10 and full matrix 129/150 valid plans.
3. **Qwen usability:** no—0/10 outputs were usable; all were empty. This is interface failure, not containment.
4. **Rollback containment:** unchanged—forced rejection achieved 72/72 integrity, zero persistent state, and zero effects.
5. **PolicyV2 regression:** yes, materially. Recall changed from 69/75 (92.0%) to 51/72 (70.8%); persistent compromise rose from 6/75 (8.0%) to 21/72 (29.2%). No policy was retuned.
6. **Stage 12 compatibility:** provenance/COW passed 129/129; flow passed 9/9; selective mixed replay passed 6/6; lineage roots passed 6/6.
7. **Live denominators:** 150 Llama generations, 129 valid, 72 malicious evaluable/compromised, 57 benign evaluable; Qwen gate 10 with zero valid; delayed pilot 5/5 evaluable.
8. **Safe paper metrics:** deterministic regression and fingerprints; exact Llama parse/policy/rollback counts; forced-rejection 72-plan containment; explicitly labeled compatibility and delayed-pilot counts; conditional component timings.
9. **Small/N/A metrics:** Qwen policy/security metrics are N/A; five delayed cases and six selective/lineage cases are pilots, not general estimates.
10. **Prominent limitations:** one qualified model, structured-plan dependence, model-output variability, materially lower final policy recall, explicit lineage only, simulated effects, in-memory recovery, and no reversal of irreversible effects.

## Decision

**MORE_VALIDATION_REQUIRED.** The runtime and rollback claims are stable, but the material live PolicyV2 regression must be reproduced and explained before freezing paper claims. The next work should be validation analysis or paper revision—not a new runtime feature stage.
