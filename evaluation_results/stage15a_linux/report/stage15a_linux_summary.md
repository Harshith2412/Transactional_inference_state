# Stage 15A Linux Summary

CRIU 4.2.1 exactly restored both the tool and RAG/cache service after unsafe
mutations. Pre-checkpoint and restored SHA-256 digests match; mutated digests
differ. CRIU completed 20/20 state-size trials across 1–100 MB and all mutation
density trials. It required a privileged Docker/LinuxKit container.

DMTCP 4.2.0 created checkpoints for both services, but restart returned without
a live participant. It therefore failed restore integrity despite successful
checkpoint and restart command exit statuses.

Linux pytest: 485 passed, 1 skipped, 0 failed. macOS pytest remains 484 passed,
2 skipped, 0 failed; the difference is the Linux-only backend probe test.

Stage 15B integration is not yet justified. CRIU is the primary candidate and
DMTCP remains a secondary comparison backend.
