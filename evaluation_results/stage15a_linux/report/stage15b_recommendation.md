# Stage 15B Recommendation

```text
Stage15BRecommendation(
    criu_status="PARTIALLY_SUITABLE",
    dmtcp_status="NOT_SUITABLE",
    primary_backend="CRIU",
    integration_justified=False,
)
```

CRIU passed individual exact-state restoration and size/density measurements.
Integration remains gated on a dedicated 50-cycle sequence, simultaneous
multi-service testing, socket participant-adapter behavior, and native negative
boundary/failure experiments. DMTCP did not restore a reachable participant.
