# Stage 13D Summary

All 13 required crash boundaries recovered with zero incorrect state commits,
zero lost committed state, zero duplicate effects, and zero provenance, lineage,
or quarantine mismatches. One deliberately ambiguous effect was reported as
`EFFECT_OUTCOME_UNKNOWN`. Historical-record modification was detected as
`JOURNAL_CORRUPTION`.

The flagship crash before effect execution restored committed authorization
state and replayed the pending email once. Crashing after execution but before
completion retained the execution receipt and suppressed duplicate delivery.

Measured append medians for 100/1,000/10,000 records were 50.31/47.50/48.75 µs;
startup verification/replay was 1.06/10.32/94.23 ms and journal size was
31,172/314,673/3,176,674 bytes. Median transaction latency was 0.125 µs for the
minimal disabled control, 288.08 µs buffered, and 408.27 µs with per-record
fsync. These local measurements are machine- and filesystem-specific.

The trusted core grows from 13 modules and 3,087 Python LOC to 14 modules and
3,547 LOC. The journal/recovery module is 460 LOC and has zero third-party core
runtime dependencies. Policy and validator code was unchanged.
