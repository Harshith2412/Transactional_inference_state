# Stage 12C measured summary

Flow-policy unauthorized attempts: 10; blocked: 10; leaked: 0. Valid flows: 1; false blocks: 0. Dirty reads prevented by transaction isolation: 1 (not counted as policy blocks).

Across three repetitions at 10, 25, 50, and 100 sessions, see `../concurrency/summary.csv`. Conflict aborts are not counted as information-flow decisions.
