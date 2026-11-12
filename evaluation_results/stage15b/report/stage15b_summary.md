# Stage 15B summary

One validated `ELIGIBLE_SINGLE_PROCESS` participant was integrated through a coordinated checkpoint lifecycle. Native tool and RAG rollback restored exact structural state and SHA-256 digests. The local-only comparison retained external contamination; the expanded boundary removed it. A deliberately damaged CRIU image produced `EXTERNAL_ROLLBACK_FAILED`, never `ROLLED_BACK`.

This is not a distributed or atomic multi-resource transaction. Native evidence is limited to privileged Docker Desktop LinuxKit arm64. Persistent clients do not survive; fresh reconnect is mandatory.
