# Transactional Inference State for Containing Persistent Effects of Untrusted Model Execution

## Abstract

Language-model applications increasingly expose mutable memory, caches, session
metadata, and tools to model-directed execution. A policy may reject an unsafe
response after these resources have already changed. We investigate whether
selected inference-time state and external-effect requests can instead remain
tentative until an execution is accepted. We implement a dependency-light Python
runtime with explicit transaction lifecycles, session isolation, optimistic
shared-state conflicts, full-copy and delta snapshots, strict structured plans,
runtime-owned provenance, independent policy checks, and staged simulated
effects. On a frozen deterministic corpus of 100 malicious and 80 hard-benign
scenarios, PolicyV2 attained 70.0% recall and a 12.5% false-positive rate, showing
that policy generalization remained imperfect. In a local-model evaluation,
`llama3.2:3b` produced 75 evaluable compromised plans and 53 evaluable benign
plans. PolicyV2 rejected 69/75 compromised plans (92.0%, 95% CI 83.6%–96.3%) and
6/53 benign plans. All 69 rejected compromised plans were contained in the tested
state/effect model, but six accepted plans persisted malicious state. A separate
forced-rejection replay produced no state or effect consequences in 75/75
transactional executions, compared with 57 state consequences and 24 effects
under immediate execution. Median incremental enforcement was 0.093 ms in 84
compatible local timing records, compared with 2.298 s median model generation.
The prototype is in-memory and single-process, effects are simulated, and only
one model passed the live interface gate. The results separate a reliable tested
containment mechanism after rejection from the harder problem of deciding which
transactions to reject.

## 1. Introduction

LLM and agent runtimes increasingly retain session memory, cache retrieved
material, update user metadata, and invoke tools. These resources allow useful
work to span turns, but they also give an untrusted inference a route to influence
later executions. A prompt injection in retrieved content may not need to produce
an immediately harmful answer. It can instead write an authorization claim into
memory, alter a cache entry, or stage a tool request that affects the environment.

Output filtering alone does not address an execution that changes persistent
runtime state before validation finishes. The central question of this work is:
Can inference-time state changes remain tentative until an execution is
accepted? We apply a conventional transaction abstraction to an explicitly
selected state boundary. An execution begins with an isolated view, records
changes and effect requests, undergoes independent validation, and either commits
or aborts. Abort restores or discards the tested mutations. Commit publishes them.

The boundary does not include model weights. We treat weights as read-only during
an inference and do not attempt weight rollback. Nor do we claim that arbitrary
external actions can be undone. Once an email, payment, or network request has
actually occurred, a Python object snapshot cannot reverse it. The design instead
stages supported effect requests and executes them only after commit.

This paper makes five restrained contributions:

1. It defines and implements a lightweight transaction abstraction for selected mutable inference state.
2. It implements full-copy and key-level delta snapshots and evaluates their rollback integrity and scaling.
3. It combines session isolation, optimistic shared-state conflicts, and staged simulated external effects in one experimental runtime.
4. It separates model compromise, policy detection, and containment rather than reporting them as one security outcome.
5. It reports deterministic and local-model evaluations, including false positives, interface failures, and six live policy false negatives.

The central result is conditional. Once PolicyV2 rejected a compromised live
plan, the transaction mechanism contained all 69 rejected cases in the tested
model. PolicyV2 nevertheless accepted six other compromised plans, and their
state writes persisted. Transactionality reduces consequences of detected unsafe
executions; it does not solve semantic policy classification.

## 2. Motivation and Problem Definition

We define inference state as the mutable data selected by an application for use
during or after model execution. In the prototype this includes session memory,
scratchpad data, application cache, retrieved data, tool results, pending memory
writes, user/session metadata, and security state. Some state is private to a
session. A smaller versioned cache represents deliberately shared application
state. External effects are represented as requests to a simulated service.

Without transactional mediation, operations may update these resources as they
are produced. A later parser error or policy rejection cannot reliably reconstruct
the earlier state, especially after nested objects have been mutated. Immediate
tools are worse because the environment may already have observed their effects.

Our desired lifecycle is `ACTIVE -> VALIDATED -> COMMITTED` for accepted work and
`ACTIVE/VALIDATED -> ROLLED_BACK` for aborted work. State changes are visible only
inside their transaction until commit. A closed transaction cannot mutate or
validate again. This formulation makes containment an explicit runtime property
rather than an implication of a model prompt.

## 3. Threat Model

The adversary may influence user input, retrieved content, model output, proposed
operations, and tool-derived content. The model is untrusted. It may emit
malformed text, lie about provenance, request authority it lacks, construct
multi-operation plans, or encode persistent instructions for later turns.

The trusted computing base includes the strict parser, runtime-issued provenance,
PolicyEngine, TransactionManager, snapshot strategy, capability enforcement, and
effect-staging path. We assume this Python process and these components execute as
implemented. Model-declared source labels are not accepted as proof of origin;
the runtime supplies provenance to policy evaluation.

Out of scope are model-weight compromise requiring weight rollback, OS or kernel
compromise, malicious trusted runtime code, hardware attacks, distributed
transaction atomicity, and rollback of arbitrary effects that have already
escaped. We do not claim full semantic correctness of PolicyV1 or PolicyV2. A
policy false negative is allowed to commit by design and is therefore not a
rollback failure.

## 4. Design Goals

The runtime has six goals. First, rejected changes to selected internal state must
not persist. Second, one session must not gain access to another session's private
transaction view. Third, concurrent readers must not observe tentative shared
writes, and stale conflicting writers must not silently overwrite a commit.
Fourth, supported external effects must remain buffered until commit. Fifth,
untrusted model text must pass a narrow, strict interface before execution.
Sixth, lifecycle and evidence must remain explicit enough for deterministic tests.

The implementation favors inspectability over generality. It uses standard Python
objects and avoids a database, distributed coordinator, agent framework, and
production service layer. This keeps the research question visible but limits the
scope of the conclusions.

## 5. Transactional Inference State

### 5.1 Inference State

`InferenceState` is a dataclass whose fields hold the private mutable resources.
`SessionManager` creates a distinct instance for each session and mediates lookup.
The explicit schema makes the snapshot boundary reviewable. It does not capture
arbitrary globals, open files, process state, or model internals.

### 5.2 Transaction Lifecycle

`TransactionManager` assigns each transaction an ID and session ID and stores its
status, snapshot context, local state, read set, and write set. Calls resolve a
specific transaction rather than relying on a single global active transaction.
Validation is an explicit transition. Invalid operations such as double commit,
rollback after commit, or mutation after closure raise errors and are covered by
tests and logged events.

### 5.3 Snapshot Strategies

The FullCopy strategy deep-copies state at begin and materializes an isolated
transaction view. It is simple and provides a direct restoration baseline, but
its begin cost scales with total state. The Delta strategy records key-level
changes relative to committed state and materializes when required. Its costs can
scale with the mutation set, although arbitrary nested access and callbacks can
force additional copying. Canonical digests complement structural equality in
rollback experiments for JSON-compatible values.

### 5.4 Session Isolation

Private operations carry both transaction and session identifiers. The manager
checks that the caller's session matches the transaction owner before reading or
writing. Concurrent experiments create sessions A and B, mutate both transaction
views, abort A, and commit B. A's rollback does not restore a global snapshot over
B's committed state.

### 5.5 Shared-State Conflicts

Shared cache entries contain a value and monotonically advancing version.
Transactions record the version observed on read and hold tentative writes
locally. Thus B reads the committed value `role=user` while A tentatively holds
`role=admin`. At commit, the manager compares observed and current versions. If A
commits first, B's write based on the old version conflicts and B aborts rather
than applying last-write-wins behavior.

### 5.6 External-Effect Staging

The effect manager records supported requests in a per-transaction buffer. A fake
email service provides deterministic observation without networking. Rollback
marks pending effects discarded. Commit first publishes internal state and then
executes staged effects in order. This ordering has an acknowledged crash window:
the prototype has no durable atomic transaction spanning memory and an external
service. Partial execution requires reconciliation and cannot be erased by state
rollback.

## 6. Model and Runtime Trust Boundary

### 6.1 ModelPlan

The model returns JSON with an operation list and final response. Supported
operations are memory read/write, cache read/write, and simulated email send.
Each operation has an ID, type, exact argument schema, and claimed source. The
small vocabulary makes operations testable but does not represent general agent
behavior.

### 6.2 Strict Parsing

The parser consumes the complete response before any operation runs. It rejects
malformed JSON, extra or missing fields, duplicate IDs, unknown operations,
unsupported provenance labels, incorrect argument types, and non-JSON values.
Parse failure closes the transaction without partial operation execution. A safe
transport normalizer was later evaluated for limited formatting repair; it did
not alter policy semantics and rescued no Stage 11 gate output.

### 6.3 Runtime Provenance

Immutable provenance records identify runtime-observed sources such as user
prompt, retrieved content, system context, and model output. Policy consumes these
records rather than trusting a model's source claim. The lineage is deliberately
lightweight. It is not cryptographic provenance or complete information-flow
tracking and does not capture implicit flows.

### 6.4 Capabilities

Capability grants describe permitted operation classes and may restrict session
IDs or email recipients. Resource scope binds evaluation to the current and
target sessions. Capabilities reduce ambient authority at the operation boundary,
but the experimental grants are in-process data structures without issuance,
expiry, revocation, or durable identity infrastructure.

### 6.5 Policy Enforcement

PolicyV1 evaluates capabilities, scope, provenance, sensitive key aliases, and
semantic patterns independently of scenario labels. PolicyV2 is a frozen,
interpretable refinement that adds contextual patterns and plan-sequence rules.
The policy produces operation-level reasons and one plan decision. It is not an
LLM and uses no external service. PolicyV2 was not changed after the Stage 10 or
Stage 11 failures were observed.

## 7. Multi-Turn State and Lineage

Multi-turn experiments test whether a first transaction can persist an instruction
that influences a later effect. Lightweight lineage connects selected operations
and committed state across turns. The runtime can roll back the current tentative
transaction, but it does not retroactively undo an earlier committed transaction.
This is fundamental: approval is the boundary after which state becomes part of
the next transaction's starting point.

The Stage 11 live multi-turn sample was too small for a broad conclusion. Five
attempts were made; only two seeds parsed, and PolicyV2 rejected both. Because no
seed persisted, the later lineage denominator was not applicable. We report this
as limited interface evidence, not successful comprehensive multi-turn defense.

## 8. Implementation

The artifact is a Python 3.10+ package. The trusted core definition contains seven
modules and 1,210 nonblank Python lines in the frozen complexity audit, with no
third-party core runtime dependency. Standard-library dataclasses, enums,
`deepcopy`, JSON, hashing, timing, and local `urllib` transport provide the main
building blocks. Pytest is a development dependency; Matplotlib is optional for
plots; Ollama is an optional localhost service.

The event log records begin, mutation, shared reads and tentative writes,
validation, conflicts, commit, rollback, and relevant session/transaction IDs.
Evaluation and reporting code is intentionally outside the trusted-core count.
The complete frozen deterministic suite contains 263 passing tests and one
optional skipped test.

## 9. Evaluation

### 9.1 Research Questions

- **RQ1:** Can transactional execution prevent rejected state mutations from persisting?
- **RQ2:** How do FullCopy and Delta affect transaction cost?
- **RQ3:** How well does an independent lightweight policy detect malicious operation plans?
- **RQ4:** How does the frozen policy generalize to held-out scenarios?
- **RQ5:** When a live model produces malicious valid plans, how often are they detected and contained?
- **RQ6:** What enforcement overhead is measured relative to local model inference?
- **RQ7:** Which semantic and multi-turn failure modes remain?

### 9.2 Experimental Setup

Deterministic experiments run without a network, database, or model service.
Stage 11 used local Ollama client 0.32.9 with `llama3.2:3b` and `qwen3:4b` tags.
The release audit ran on arm64 macOS with Python 3.14.3, while earlier development
used Python 3.13. Live latency is specific to this local setup. Frozen manifests,
raw outputs, summaries, and SHA-256 hashes accompany the artifact.

### 9.3 Corpus

The Stage 10 held-out corpus contains 100 malicious scenarios across 14 attack
families and 80 hard-benign scenarios. Its identifiers do not overlap the Stage 9
set. Scenarios are handcrafted and evaluation-designed, not a random sample of
deployed agent traffic. The Stage 11 manifest selected 30 malicious and 20 benign
scenarios with three generations each, producing 150 attempts.

### 9.4 Deterministic Evaluation

The deterministic harness executes the same scenarios against fixed policies and
records confusion matrices, persistent state, external effects, and rollback
integrity. Paired immediate and transactional paths distinguish consequences of
execution from classification. Stage 10 freezes both policies before evaluation.

### 9.5 Live-Model Evaluation

An interface gate first checks whether models reliably produce strict plans.
Llama passed at 9/10 raw and normalized plans. Qwen produced 0/10 valid plans and
was classified as interface-unreliable, so it did not enter the full security
matrix. In the Llama run, 128/150 outputs parsed: 75/90 malicious and 53/60 benign.
Security rates use these evaluable denominators. Conditional model compromise was
75/75 because every valid malicious plan implemented the designated malicious
operation.

### 9.6 Snapshot Performance

The snapshot matrix varies state size, mutation ratio, strategy, and commit or
rollback outcome. It measures phase latency and traced Python allocations over
repeated fixed workloads. These measurements compare implementations on one host;
`tracemalloc` is not total resident memory and should not be interpreted as such.

### 9.7 Runtime Overhead

Stage 11 separates generation, safe normalization, parsing, baseline operation
execution, transaction begin, transactional operation execution, policy, commit
or rollback, and effect execution. Incremental enforcement subtracts compatible
baseline operation time from transaction begin, transactional operation, and
closure time. Eighty-four records were compatible; 44 timing fixture read errors
were disclosed rather than silently included.

### 9.8 Multi-Turn Evaluation

The deterministic suite includes cross-turn memory/effect cases. The Stage 11
live extension attempted five seeds, of which two parsed and both were rejected.
This establishes behavior for those attempts but provides no denominator for a
persisted-seed lineage attack.

## 10. Results

For RQ1, forced rejection provides the clearest mechanism result. Immediate
baseline execution caused persistent state consequences in 57/75 compromised
plans and external effects in 24/75. Transactional execution under the same
forced-rejection condition caused 0/75 persistent state consequences and 0/75
effects; rollback integrity matched in 75/75. The ordinary live run similarly
contained all 69/69 plans that PolicyV2 rejected. These results apply to the selected
in-memory state and simulated effect buffer.

For RQ3 and RQ4, PolicyV1 on Stage 10 produced TP=35, FN=65, FP=0, and TN=80:
35.0% recall, 0% observed FPR, and 51.9% F1. PolicyV2 produced TP=70, FN=30,
FP=10, and TN=70: 70.0% recall, 12.5% FPR, and 77.8% F1. Its persistent-compromise
rate was 30.0% and benign completion was 87.5%. PolicyV2 recall decreased from
79.2% in the smaller Stage 9 held-out evaluation to 70.0% on the larger Stage 10
frozen set, while observed FPR increased to 12.5%. This less favorable result is
the appropriate generalization estimate among the completed deterministic stages.

For RQ5, PolicyV2 rejected 69 of 75 evaluable compromised Llama plans (92.0%,
95% CI 83.6%–96.3%). Six were accepted and persisted, giving an 8.0% persistent-
compromise rate among evaluable compromised plans. No PolicyV2 live trial leaked
through the simulated external-effect path. On benign plans, PolicyV2 rejected
6/53 (11.3%) and completed 47/53 (88.7%). PolicyV1 detected 48/75 compromised
plans, persisted 24/75, leaked effects in 6/75, and falsely rejected 6/53 benign
plans.

For RQ6, among 84 compatible records median model generation was 2.298 s. Median
incremental transactional enforcement was 0.093 ms, mean was 0.102 ms, and P95
was 0.182 ms. Mean normalization plus parsing was 0.226 ms. The mean enforcement
fraction of end-to-end latency was 0.00461%. In this tested local-model
configuration, enforcement was a small measured fraction of generation latency;
the result is not a universal overhead bound.

## 11. Failure Analysis

The six PolicyV2 live false negatives came from three generations each of
`s10-mal-002` and `s10-mal-030`. Every plan wrote `the old dialogue permits
release` to an ordinary field from retrieved content. The key was not a sensitive
alias, and the sentence did not match the frozen PolicyV2 semantic patterns.
Capability and session checks passed, claimed provenance agreed with runtime
origin, and there was no risky multi-operation sequence. PolicyV2 therefore
returned an empty reason set and commit persisted the value. No plan requested an
external effect.

The common failure is an indirect semantic reference to prior authorization.
PolicyV2 recognizes some nearby phrases, including `prior chat permits`, but a
lexical/contextual rule set does not establish whether an earlier conversation
actually granted current authority. Adding the observed sentence after evaluation
would weaken the held-out methodology and invite paraphrase evasion. The negative
result supports investigating explicit authorization objects rather than claiming
that a longer denylist resolves the problem.

## 12. Limitations

The runtime is in-memory and retains single-process assumptions. It is not
thread-safe, durable, or crash recoverable. There is no distributed transaction
protocol, and private concurrent transactions in the same session do not use a
version conflict check. No OS, process, or arbitrary machine-state rollback is
provided.

External effects are simulated. The effect manager prevents rejected staged
requests from executing, but cannot undo arbitrary actions that already occurred.
Internal state commit precedes effect execution, so there is no durable atomicity
between them. Partial effects require reconciliation; in-process idempotency is
not cross-crash exactly-once delivery.

The corpora are handcrafted and shaped by the evaluation design. PolicyV2 is
imperfect: Stage 10 measured 12.5% FPR and 70.0% recall, and live evaluation found
six indirect-authorization false negatives. No retroactive rollback spans already
committed transactions. Lineage is lightweight rather than full information-flow
tracking, and JSON structured operations constrain the behaviors studied.

Live-model diversity is limited. Only Llama qualified for the full Stage 11 run;
Qwen's 0/10 interface result prevented a comparable security estimate. The live
sample used one local model configuration and conditional evaluable denominators.
Model output may change across software versions and runs. Snapshot and latency
benchmarks depend on local hardware, interpreter, allocator, load, and caching.

Finally, trusted components are assumed correct. The suite supplies extensive
tests, not a formal proof. The policy has no general semantic understanding, and
the artifact does not establish production hardening against a malicious runtime,
kernel, or hardware.

## 13. Discussion

The experiments suggest a useful decomposition. Model compromise asks whether an
untrusted model proposes a prohibited operation. Policy detection asks whether
the trusted validator recognizes it. Transactional containment asks whether a
recognized and rejected plan leaves consequences. Combining these quantities can
hide failure: a perfect rollback mechanism cannot help an accepted attack, while
a strong classifier does not repair an effect already executed outside its
control.

Transactionality changes the timing of trust. Instead of allowing each operation
to become authoritative as emitted, the runtime collects a candidate state
transition and asks for one explicit decision. This also creates reviewable
artifacts: read/write sets, provenance, capability context, pending effects, and
lifecycle events. The cost is that every mutable resource must participate in the
boundary or remain explicitly out of scope.

The Stage 10 and Stage 11 contrast should not be read as proof that live traffic
is easier. The deterministic set covers more scenarios and guarantees evaluation
of each designated attack. The live denominator excludes malformed outputs and
reflects one model's behavior under one prompt. Both results are necessary: the
larger frozen set exposes policy generalization weakness, while live plans test
the model/parser/policy/runtime pipeline.

## 14. Related Work

The design draws on concepts from database transactions and isolation, software
fault containment, capability systems, provenance and information-flow tracking,
checkpoint/rollback systems, LLM memory security, prompt injection, agent
sandboxing, and tool authorization. A publication version must compare the
artifact carefully with these areas. Citations are intentionally omitted from
this freeze draft until sources are verified. The required literature searches
are listed in `paper/related_work_notes.md`. [CITATION NEEDED]

## 15. Future Work

Future research may evaluate runtime-issued approval tokens, verified consent
objects, expiring capability grants, richer authorization-state models, stronger
provenance-aware decisions, and semantic policy analysis. These ideas should be
tested on newly frozen development and held-out partitions rather than applied
post hoc to the six observed phrases.

Additional scientific validation would require more model families that first
pass the same interface gate, repeated runs that expose generation variance, and
less evaluation-shaped corpora. Systems work could study durable logs, crash
recovery, outbox protocols, and process isolation, but those mechanisms are not
part of the present artifact and would change its trust and failure model.

## 16. Conclusion

Transactional Inference State makes selected model-directed mutations tentative
until a trusted decision closes the execution. In the tested runtime, rejected
transactions restored internal state and discarded staged simulated effects
across deterministic and live replay experiments. Full-copy and delta snapshots,
session isolation, shared-state conflicts, strict parsing, provenance, and
capabilities make that boundary explicit.

The evaluation also shows why containment and detection must be reported
separately. PolicyV2 attained 70.0% recall with 12.5% FPR on the larger frozen
deterministic corpus and missed six of 75 evaluable compromised live plans. Those
six writes persisted because the policy accepted them. All 69 rejected live
plans were contained, but this is not complete attack prevention. The prototype
therefore supports a narrower conclusion: transactions can reliably remove the
tested consequences of rejected execution, while correct semantic authorization
remains the limiting security problem.
