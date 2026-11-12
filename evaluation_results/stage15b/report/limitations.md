# Limitations

Supported scope is exactly one externally managed single process. Filesystem-dependent state, unmanaged effects, persistent-socket requirements, arbitrary process trees, atomic multi-service groups, remote effects, and connection-transparent rollback are unsupported. The adapter depends on privileged CRIU/Linux facilities. A crash after successful restore but before a complete journal record requires re-verification; an incomplete restore requires an explicit retry.
