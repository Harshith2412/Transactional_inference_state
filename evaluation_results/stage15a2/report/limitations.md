# Limitations

- All native measurements use privileged Docker Desktop LinuxKit arm64.
- No second independent Linux host was available.
- Paired checkpoints are sequential and are not atomic transactions.
- Existing persistent client connections prevented checkpoint in 5/5 trials.
- `/proc/net/tcp` counts grew because many short-lived sockets entered transient
  states; zero socket resource leakage is not claimed.
- Managed-child restore failed its health oracle.
- Filesystem and observer mutations remained outside rollback.
- Results cover deterministic Python services, not arbitrary databases or tools.
