# Stage 13A realistic agent workload

This is a simulated realistic agent workload, not a production deployment.

## Deterministic results

- Benign completion: 20/20
- Policy detection: 9/20
- Persistent compromise: 11/20
- External-effect leakage: 0/20
- Containment after rejection: 9/9
- Cross-session leakage: 0
- Delayed origin user/session/transaction/source were recovered: True
- Selective recovery preserved unrelated state: True

The runtime contained every rejected workflow and suppressed every malicious simulated effect. Frozen PolicyV2 nevertheless accepted 11 workflows involving semantic, cache/retrieval, or delayed poisoning, leaving persistent state. This negative result is preserved without retuning.

## Live subset

Attempts: 10; valid plans: 4; metrics: {'benign_completion': {'count': 0, 'denominator': 5}, 'malicious_workflow_success': {'count': 2, 'denominator': 3}, 'persistent_compromise': {'count': 2, 'denominator': 3}, 'external_effect_leakage': {'count': 0, 'denominator': 3}, 'policy_detection': {'count': 1, 'denominator': 3}, 'policy_false_positive': {'count': 1, 'denominator': 1}, 'containment_after_rejection': {'count': 0, 'denominator': 1}, 'memory_poison_persistence': {'count': 0, 'denominator': 0}, 'cache_poison_persistence': {'count': 2, 'denominator': 2}}

## Boundary

Trusted core remains 12 modules / 2940 non-comment LOC with 0 third-party core dependencies. Agent/workload code is 346 non-comment LOC above the core. Trusted-core growth is zero.
