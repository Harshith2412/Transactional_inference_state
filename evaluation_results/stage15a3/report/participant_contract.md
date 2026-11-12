# Participant Contract

Eligible participants must have one managed process, mutation quiescing,
successful CRIU checkpoint/restore, reachable health check, structural and
digest state oracles, observable restore failure, stable endpoint, and fresh
reconnect support. They must not depend on CRIU reverting mutable filesystem
state or unmanaged external effects.

Process trees, persistent-client requirements, and atomic multi-service groups
are outside the supported contract. A restore is successful only after backend,
health, structure, digest, eligibility, endpoint, and reconnect checks pass.
