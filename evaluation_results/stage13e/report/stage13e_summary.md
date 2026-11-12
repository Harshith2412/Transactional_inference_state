# Stage 13E Summary

Three-repetition experiments covered 100, 500, and 1,000 simultaneous coroutine
sessions, LOW/MEDIUM/HIGH contention, disabled/buffered/fsync journal modes, a
1,000-session flow stress, and 500-session recovery stress.

Low-contention median attempted throughput was 1,310.31, 1,248.39, and 1,164.10
transactions/s at 100, 500, and 1,000 sessions. Median p95 latency was 55.45,
285.51, and 619.13 ms; p99 was 57.00, 292.28, and 633.64 ms. At 1,000 sessions,
MEDIUM and HIGH contention aborted 90% and 98.89% of shared write attempts.

All reported unauthorized flows were blocked with zero leakage. Sentinel,
capability, provenance, lineage, rollback, effect-duplication, and journal
correctness failures were zero. Public/declassified controls remained allowed.

At 1,000 sessions, median throughput was 1,091.29 tx/s without journaling,
454.00 buffered, and 428.21 with per-record fsync. Corresponding p95 latency was
673.54, 1,620.64, and 1,734.03 ms. The 500-session restart recovered 250/250
committed transactions and discarded 250/250 uncommitted transactions.

Trusted core growth is zero. The 191-line Stage 13E module is evaluation code;
the trusted core remains 14 modules, 3,547 LOC, and zero third-party runtime
dependencies.
