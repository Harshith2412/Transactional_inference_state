# Limitations

- macOS cannot natively execute CRIU or DMTCP.
- CI oracle restore is not process checkpoint evidence.
- Socket survival, PID behavior, image size, latency, and repeated cycles remain unmeasured.
- Process restore does not imply filesystem, remote API, email, banking, or unmanaged-service rollback.
- Coordinated multi-process atomicity was not demonstrated.
