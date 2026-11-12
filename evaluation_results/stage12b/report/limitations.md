# Stage 12B limitations

Synthetic in-memory benchmark; one iteration per matrix cell; node-copy accounting is strategy-aware but approximate; `tracemalloc` is not RSS; explicit COW paths only; arbitrary callbacks fully materialize; private state is field-granular while shared conflicts remain key-granular; no thread safety, durability, automatic dependency inference, or dynamic taint analysis.
