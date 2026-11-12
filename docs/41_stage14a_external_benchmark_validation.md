# Stage 14A — External Benchmark Validation

Stage 14A evaluates frozen runtime mechanisms against externally authored task
concepts. It does not add runtime or detection behavior, and it does not claim a
full run of either upstream benchmark.

## Selection and sources

The primary subset is Agent Security Bench (ASB) memory poisoning: ten malicious
agent/tool goals and ten matched benign agent-task controls from official commit
`1f561dccf92d55302368fa67679b4ba9d9c8fdc4`. ASB defines memory poisoning as
malicious content retrieved from agent memory during planning.

The secondary subset contains ten malicious injection goals and ten benign
controls from AgentDojo v1 workspace/travel tasks at commit
`089ed468cf3ed0322acc66b0211f26d9d90dbf60`. AgentDojo evaluates indirect prompt
injection inside sandboxed tool environments. Both upstream repositories use the
MIT license.

Sources:

- https://github.com/agiresearch/ASB
- https://github.com/ethz-spylab/agentdojo
- ASB paper: https://arxiv.org/abs/2410.02644
- AgentDojo paper: https://arxiv.org/abs/2406.13352

MemSecBench's public paper informed the lifecycle terminology, but its 310-case
dataset was not selected and is explicitly not claimed as evaluated.

## Adaptation

ASB vector-memory write and retrieval become authoritative local memory writes
and later transaction reads. The original malicious instruction and attack goal
remain unchanged. AgentDojo email goals use the existing simulated email effect;
file, calendar, booking, and cancellation goals use an in-memory workspace/cache
projection. Six such mappings are marked `ADAPTER_ONLY_TRANSFORM`, not clean
authoritative propagation. Real services, credentials, browsers, banking
transfers, hosted models, AIOS, and vector databases are excluded and recorded
in `corpus/excluded_tasks.json`.

This is an adapted task-concept evaluation, not execution inside the original
ASB or AgentDojo harnesses. Ground-truth labels and attack-family names remain in
the evaluator and are absent from `ValidatorEvidence`.

## Method

The external manifest was written and frozen before validator execution. Its
SHA-256 is `858e466e3673571f2f0a518b5125dd5e57ecd3883688f40ed22267b95777c61e`.
Frozen PolicyV2, Sequence, Provenance, Semantic, and Hybrid validators receive
only strict plans, authoritative runtime sources, scope, dependencies, and gap
state.

The primary lifecycle keeps WRITE, PERSIST, RETRIEVE/REUSE, and REPAIR as
separate observations. Accepted malicious values are committed in one
transaction and consumed later. Recovery builds a task-specific causal graph,
checks its known source, derives a recovery plan, applies quarantine/invalidation,
preserves unrelated state, and verifies that later reuse is blocked.

Immediate, policy-only, transactional, and forced-rejection outcomes are kept
separate. Parser failure is never counted as containment.

## Results

Across all 20 malicious and 20 benign tasks:

| Validator | TP/FN | FP/TN | Recall | FPR |
|---|---:|---:|---:|---:|
| PolicyV2 | 5/15 | 0/20 | 25% | 0% |
| Sequence | 0/20 | 0/20 | 0% | 0% |
| Provenance | 20/0 | 0/20 | 100% | 0% |
| Semantic | 0/20 | 0/20 | 0% | 0% |
| Hybrid | 20/0 | 0/20 | 100% | 0% |

Results differ by benchmark. PolicyV2 recall is 0/10 on ASB memory tasks and
5/10 on AgentDojo concepts. Under PolicyV2, all ten ASB poisons persist while all
ten controls complete. Forced transactional rejection contains 20/20 malicious
tasks with exact rollback and no simulated effect. This supports the mechanism's
conditional containment claim but shows that policy misses remain decisive.

All ten accepted ASB memory cases have task-specific causal ground truth. Root
origin, contaminated state, unrelated-state preservation, and blocked reuse each
succeed in 10/10 recovery runs. This result applies to the local adaptation, not
all upstream benchmark cases.

Automatic instrumentation classification covers 34/40 tasks authoritatively.
Six adapter-only transforms yield 85% coverage and a 15% gap rate. No unsupported
operation is silently counted as defended; unsupported upstream tasks remain in
the exclusion log.

## Cross-workload interpretation and limitations

The internal realistic-agent PolicyV2 recall was 45%, versus 25% across this
external subset and 0% on the primary memory subset. Internal persistent
compromise was 55%; the adapted primary subset is 100% because PolicyV2 misses
all ten memory-write attacks. These distributions differ and the comparison is
descriptive, not apples-to-apples.

The deterministic adapter does not execute upstream model prompts, original
vector search, full sandbox state, or real APIs. Some task semantics are reduced
to local state/effect equivalents. The provenance validator's perfect result on
this subset reflects authoritative untrusted-source labels and should not be
generalized. No optional live Llama run was used. Latency is local adapter/runtime
latency, not upstream benchmark latency. The external adapter/evaluator is 177
LOC outside the trusted core; trusted core remains 14 modules and 3,547 LOC.
