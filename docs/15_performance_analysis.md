# Performance and snapshot analysis

Deterministic paired execution measured mean transactional-minus-baseline total
latency of 55,275 ns and transaction/runtime difference of 43,553 ns. The
deterministic adapter is nearly free, so transaction work is proportionally
prominent; real-model inference dominates end-to-end latency and must be read
separately.

The full matrix is 5 sizes × 6 ratios × 2 strategies × 2 outcomes × 7 iterations
= 120 cells. Representative 5% commit means:

| State | FullCopy | Delta |
|---|---:|---:|
| 10 KB | 184,410 ns | 85,851 ns |
| 100 KB | 194,054 ns | 85,482 ns |
| 1 MB | 352,780 ns | 141,601 ns |
| 10 MB | 2,194,756 ns | 754,577 ns |
| 50 MB | 10,770,566 ns | 3,435,423 ns |

Observed crossover occurred only for 10 MB commit at 100% mutation and 50 MB
rollback at 100%. No crossover was observed in other tested size/outcome
combinations. This is empirical, not a complexity proof. All 120 cells passed
integrity checks.

`tracemalloc` reports traced Python allocation, not process RSS. Immutable values
may be shared by `deepcopy`, allocator/cache effects remain, and timings are
environment-sensitive. Raw phase metrics and mutated-key counts are in the
[snapshot matrix](../evaluation_results/snapshot_matrix/raw_results.json) and
[crossover analysis](../evaluation_results/snapshot_matrix/crossover_analysis.json).

