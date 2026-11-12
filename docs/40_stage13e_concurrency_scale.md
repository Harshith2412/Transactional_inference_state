# Stage 13E — Concurrent Session Scale Evaluation

Stage 13E is an evaluation-only layer. It changes no transaction, durability,
flow, policy, validator, provenance, lineage, or effect semantics. The trusted
core remains 14 modules and 3,547 LOC with no third-party runtime dependencies.

## Workload and execution model

The harness uses `asyncio` to establish many simultaneously active transactions
inside one Python process. Transaction preparation yields before resolution, so
shared writes observe the same pre-commit versions and exercise existing
optimistic conflict handling. This tests deterministic interleaving, not OS
thread parallelism, multiprocessing, distributed concurrency, or production
server scalability.

Each session receives tagged private state, performs nested fine-grained COW,
issues and derives authoritative provenance, records a per-session lineage DAG,
reads and tentatively writes shared cache state, and then commits, rolls back, or
quarantines. Supplemental operations follow the configured research mix: 40%
private state, 20% shared cache, 15% provenance/lineage, 10% flow checks, and 5%
each effects, selective quarantine, and conflict-heavy operations. Core safety
operations occur in every transaction; percentages describe workload emphasis,
not mutually exclusive transaction classes.

LOW uses one cache key per session, MEDIUM uses approximately one key per ten
sessions, and HIGH uses ten global hot keys. Every session also attempts an
unauthorized flow and cross-session capability/sentinel reuse. Trusted system
public data and explicitly declassified data are positive controls.

## Measured scale results

All numbers are medians over three independent runs on this local machine.

| Sessions | Attempted tx/s | p50 | p95 | p99 | Conflict rate | Flow leakage | Tracemalloc peak |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 1,310.31 | 38.92 ms | 55.45 ms | 57.00 ms | 0% | 0/300 | 1.16 MB |
| 500 | 1,248.39 | 203.04 ms | 285.51 ms | 292.28 ms | 0% | 0/1,500 | 5.98 MB |
| 1,000 | 1,164.10 | 442.40 ms | 619.13 ms | 633.64 ms | 0% | 0/3,000 | 12.01 MB |

Latency includes time waiting behind other simultaneously prepared coroutine
transactions. Attempted throughput fell about 11% from 100 to 1,000 sessions;
the measurements do not establish linear scalability.

At 1,000 sessions, median conflict-abort rates were 0% LOW, 90% MEDIUM, and
98.89% HIGH. The required HIGH run committed 10, conflict-aborted 890, rolled
back 50, and quarantined 50 transactions per repetition. Expected conflict
aborts are not correctness or security failures. Attempted transaction
throughput does not represent useful committed throughput under contention.

## Flow, provenance, lineage, and resources

Across the principal scale runs, all 4,800 unauthorized attempts were blocked
and none leaked. The dedicated 1,000-session runs blocked 3,000/3,000 attempts
per contention level across repetitions. Public and explicitly declassified
controls remained allowed; no sentinel or restricted-field leakage occurred.

Automatic provenance coverage was 100% for instrumented transforms with zero
UNKNOWN lineage and zero sampled identity mismatches. Each session created two
lineage nodes and one edge. At 1,000 sessions, serialized private state was
83,903 bytes and estimated lineage storage was 644,000 bytes. Tracemalloc peak
was approximately 12 MB; this is Python allocation tracking, not process RSS.

## Journal cost and recovery

At 1,000 sessions, median attempted throughput was 1,091.29 tx/s without a
journal, 454.00 tx/s with buffered journaling, and 428.21 tx/s with per-record
fsync. Median p95 transaction latency was 673.54 ms, 1,620.64 ms, and 1,734.03
ms respectively. The 1,000-session journal was 2,779,989 bytes. Sequence order,
hash-chain verification, and logical commit uniqueness held in every run.

The 500-session crash workload recovered 250 committed transactions and
discarded 250 uncommitted transactions. State, provenance, and lineage mismatch
counts were zero; repeated recovery was identical and effects were not
duplicated.

## Limitations

These are single-machine, single-process, coroutine-interleaving results. They
do not test multiprocessing writers or distributed execution. Tracemalloc adds
measurement overhead. Workloads and fake effects are deterministic and local.
Per-session lineage graphs avoid imposing unimplemented synchronization on the
existing graph. The benchmark reports attempted throughput; high-contention
committed throughput is much lower. Results are machine/filesystem-specific and
are not production capacity claims.
