# Stage 15A.2 Summary

- Tool integrity: 50/50 plus optional 100/100
- RAG integrity: 50/50
- Sequential barrier-group integrity: 20/20
- State drift: 0
- Port drift: 0
- Expanded state-size restores: 40/40
- Persistent-client checkpoint: 0/5
- Reconnect strategy: `RECONNECT_SUPPORTED`
- Filesystem mutation after checkpoint: persisted
- Unmanaged observer mutation: persisted
- Managed-child process-tree restore: failed health oracle
- Failure injection: fail-closed

CRIU is reliable for the measured individual Python services but remains scoped
to a privileged LinuxKit environment. Stage 15B integration remains gated.
