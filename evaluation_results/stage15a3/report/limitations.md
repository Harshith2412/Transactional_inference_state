# Limitations

- Native results remain limited to privileged Docker Desktop LinuxKit arm64.
- No second independent Linux environment was available.
- Managed-child restoration failed twice and process trees are excluded.
- Multi-service checkpoints are sequential and non-atomic.
- Persistent clients do not survive the measured checkpoint shape.
- Filesystem and unmanaged observer mutations survive participant restoration.
- Results apply to the deterministic Python services, not arbitrary databases.
