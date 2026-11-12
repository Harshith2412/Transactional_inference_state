# Stage 12D: selective commit, quarantine, and dependency-aware validation

## Scope and compatibility

Stage 12D adds an opt-in resolution path for mixed safe and unsafe mutations. The
existing `PolicyValidator` and `TransactionManager.validate()` / `commit()` path
remains whole-transaction and atomic. PolicyV1 and PolicyV2 are unchanged.

## Decision model

Trusted validators produce immutable `ValidationDecision`, `FieldDecision`, and
`EffectDecision` values. Actions are `COMMIT`, `ROLLBACK`, `QUARANTINE`,
`REQUIRE_REVIEW`, and `SELECTIVE_COMMIT`. Field decisions name a typed Stage 12B
`FieldPath` and carry reasons, optional confidence, provenance IDs, and explicit
dependency IDs. The resolver only enforces these decisions; it does not classify
content.

`ConfidenceValidator` maps trusted signed scores through configurable commit and
rollback thresholds. Scores between the thresholds use a configured uncertainty
action, which defaults to quarantine as a prototype choice rather than a universal
security threshold.

## Selective commit and dependency closure

`SelectiveTransactionResolver` requires `FineGrainedCOWStrategy` and exact decision
coverage for every modified data path. It builds a fresh COW context from committed
state and copies only approved paths into it. A proposed commit whose authoritative
lineage intersects a rejected or quarantined provenance/dependency ID is converted
to quarantine. This closure is deterministic and transitive through the explicit
provenance graph. It does not infer dependencies that the runtime did not record.

Independent siblings therefore survive: rejecting
`session_memory/authorization/external_sharing` does not remove an independent
`session_memory/preferences/editor` update. Provenance for committed paths and its
lineage is committed; other tentative provenance is discarded from normal runtime
lookup after quarantine captures its authoritative records.

## Quarantine

`QuarantineStore` retains deep-copied values, field paths, source transaction and
session, decision metadata, reasons, direct provenance, and lineage. Ordinary state
and transaction reads never consult this store. Only explicit trusted `get()` and
`list_for_transaction()` calls expose it. Quarantine is isolated retention, not
rollback or normal commit. This prototype is in memory and has no access-control or
durability layer beyond its trusted API boundary.

## Validators and composition

The interchangeable `Validator` protocol is implemented by:

- `StaticRuleValidator`, with separate Stage 12D semantic-poisoning rules;
- `ProvenanceFlowValidator`, using authoritative trust lineage;
- `SequenceValidator`, using an explicitly supplied operation sequence; and
- `ConfidenceValidator`, using configured deterministic scores.

`CompositeValidator` supports `DENY_OVERRIDES` and `ALL_MUST_APPROVE`. It records
disagreement in the result. Under the prototype deny-overrides configuration,
conflicting allow/deny votes quarantine the field. Frozen PolicyV1/V2 are not
retuned or rewritten.

## Effects and review

Pending effects now carry explicit dependency IDs and a classification of
`REVERSIBLE`, `COMPENSATABLE`, or `IRREVERSIBLE`. These are labels only; no real
compensation exists. An effect whose dependency IDs intersect rejected or
quarantined state is discarded and cannot execute. An independent approved
simulated effect may execute while safe state commits.

`REQUIRE_REVIEW` transitions to `REVIEW_REQUIRED` without committing. Explicit
trusted approval, rejection, or quarantine resolution must present the SHA-256
token bound to the transaction ID, session ID, and modified-path identity. Review
state is closed to ordinary mutation, so a stale or foreign token cannot resolve it.
There is no UI, background worker, or asynchronous review.

## Metrics and experiments

The flagship transaction proposes two benign fields and two unsafe/dependent
fields. Metrics explicitly count proposed, committed, quarantined, rejected, and
dependency-blocked fields; effect leakage; useful-state retention; malicious
persistence; quarantine; validator disagreement; and local validation/resolution
latency. Binary and selective modes each use one controlled mixed transaction.
Performance uses 5, 20, and 100 paths and reports local medians for binary rollback,
binary commit, selective commit, quarantine, review-decision creation, and dependency
closure. These small denominators do not estimate deployment behavior.

Measured output is under `evaluation_results/stage12d/`, including eight SVG figures
generated directly from the evaluation document.

## Limitations

Selective commit is not inherently safer than whole rollback. It increases semantic
and trusted-core complexity. Dependencies must be explicit; missing lineage can
permit unsafe persistence, while broad lineage can quarantine benign descendants.
The quarantine and review token registry are process-local. Selective resolution is
limited to explicit COW path mutations, shared-state selective writes are not
implemented, effects are simulated, classifications do not provide reversibility,
and measurements are local microbenchmarks. There is no LLM, external persistence,
network service, background review, or Stage 12E work.
