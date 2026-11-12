# Stage 12B measured summary

Records: 216.

| Strategy | Outcome | Median total (ms) | Median copy amplification | Integrity | Materialization |
|---|---|---:|---:|---:|---:|
| full_copy | commit | 3.105271 | 43.540 | 100.0% | 0.0% |
| full_copy | rollback | 2.009250 | 21.770 | 100.0% | 0.0% |
| delta | commit | 1.361438 | 9.000 | 100.0% | 0.0% |
| delta | rollback | 1.116333 | 6.000 | 100.0% | 0.0% |
| fine_grained_cow | commit | 0.707771 | 2.000 | 100.0% | 0.0% |
| fine_grained_cow | rollback | 0.719979 | 2.000 | 100.0% | 0.0% |

These are one-iteration, local synthetic measurements. See `limitations.md`.
