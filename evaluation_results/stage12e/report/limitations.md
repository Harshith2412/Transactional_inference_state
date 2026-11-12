# Stage 12E limitations

All dependencies are explicitly registered; no semantic or causal inference is performed. The lineage graph, quarantine, invalidation markers, and audit log are process-local. Recovery does not undo historical commits or executed irreversible effects. The 25-scenario corpus is handcrafted, graph branches are controlled, and perfect controlled-set scores are not deployment estimates. Graph storage grows without compaction. The 10,000-node measurements are local Python microbenchmarks.
