# Stage 15B Gate

```text
Stage15BRecommendation(
    criu_status="RELIABLE_WITH_SCOPED_LIMITATIONS",
    reliability_cycles=200,
    tool_integrity="150/150",
    rag_integrity="50/50",
    multiservice_integrity="20/20 sequential with barrier",
    socket_strategy="RECONNECT_SUPPORTED",
    external_boundary_limitations=[
        "filesystem mutation persists",
        "unmanaged observer mutation persists",
        "persistent clients must be invalidated",
        "managed-child restore failed",
        "privileged LinuxKit only",
    ],
    integration_justified=False,
)
```

The managed-child failure, privilege requirement, and missing second-host
validation keep the integration gate closed.
