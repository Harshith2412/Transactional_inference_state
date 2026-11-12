# Stage 13E Limitations

- Single-process asyncio interleaving is not CPU-parallel or distributed load.
- Attempted throughput overstates useful throughput during conflict collapse.
- Tracemalloc is not RSS and adds overhead.
- Measurements are machine, Python-version, and filesystem specific.
- Deterministic workloads and fake effects are not production traffic.
- Per-session lineage graphs avoid claiming untested graph thread safety.
- Journal writing is single-process; multiprocessing coordination is untested.
- Three repetitions characterize this experiment, not production capacity.
