# Research problem

A response filter may suppress a malicious final answer while leaving earlier
runtime mutations behind. Examples include poisoned memory, corrupted cache,
altered session/security metadata, future-session instructions, staged actions,
or cross-session contamination. Output rejection alone therefore does not imply
state-level containment.

Primary question:

> Can transactional semantics provide state-level containment for AI inference
> by ensuring that rejected executions leave no persistent internal mutations
> or unauthorized deferred external effects?

Secondary questions include:

- Which state belongs inside a transaction?
- What isolation is needed when transactions overlap?
- What are eager snapshot costs, and can delta tracking reduce them?
- How should irreversible actions be deferred and partial failure represented?
- Does containment continue when different untrusted models follow attacks?
- What happens when parsing, policy detection, or effect execution fails?

The hypothesis tested here is narrow: for supported operations and trusted
runtime components, tentative state/effects can be withheld and discarded after
rejection. This does not imply that the policy recognizes every attack or that
all real-world side effects are reversible.

