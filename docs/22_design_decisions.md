# Design decisions and lightweight philosophy

- **Application state, not model weights:** weights are read-only; the research
  target is mutable runtime state and action requests.
- **Python/stdlib first:** a compact implementation makes invariants and trusted
  code inspectable before adding infrastructure.
- **Deterministic adapter first:** tests must not depend on model availability.
- **Full copy before delta:** correctness was established with simple `deepcopy`;
  incremental complexity was introduced behind a common strategy later.
- **Optimistic shared conflicts:** versioned read/write sets demonstrate stale
  writer detection without locks or last-write-wins.
- **Stage effects:** irreversible actions cannot be undone by local rollback, so
  authorization is withheld until commit.
- **Strict fail-closed schema:** malformed or unsupported text grants no runtime
  capability; the parser is not loosened to improve model scores.
- **Trusted executor:** model output never directly receives or mutates manager or
  service objects.
- **Runtime provenance wins:** untrusted labels cannot self-authorize.
- **Comparable baseline:** parser/schema/policy remain; immediate visibility is
  the controlled difference where practical.

The trusted core is intentionally small: transaction/session managers, snapshot
strategy, shared state, policy, parser/executor, effect manager/proxy, runtime
provenance context, and digest. Integrations belong above or beside it.

Intentionally excluded alternatives include full process/VM snapshots, treating
database transactions as the entire solution, distributed two-phase commit,
LangChain/LangGraph dependencies, Kafka/Redis/Postgres infrastructure,
Kubernetes/cloud requirements, arbitrary Python tool execution, and real
email/network integrations. These may be future comparison points, not hidden
dependencies. The research mechanism should remain understandable without a
heavy agent framework.

