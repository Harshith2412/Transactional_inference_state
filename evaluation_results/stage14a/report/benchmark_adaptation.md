# Benchmark Adaptation

- ASB vector-memory poisoning → local authoritative memory write, later local
  retrieval, simulated consequence, and task-specific lineage recovery.
- AgentDojo email goals → existing deterministic fake-email effect.
- AgentDojo file/calendar/travel mutation → in-memory workspace/cache mutation,
  marked `ADAPTER_ONLY_TRANSFORM`.
- Attack goals and benign/malicious labels are retained for evaluation, but
  labels are never passed to validators.
- Hosted models, vector DBs, AIOS, browsers, banking transfers, credentials, and
  real services are excluded rather than approximated as successful defenses.

Both selected upstream repositories are MIT-licensed. The release stores task
metadata and concise goal descriptions, not complete upstream environments.
