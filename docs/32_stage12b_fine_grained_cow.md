# Stage 12B: fine-grained delta and copy-on-write state

## Scope and research question

Stage 12B asks whether explicit nested-field mutations can remain speculative
without eagerly copying or replacing unrelated inference state. It adds
`FineGrainedCOWStrategy` beside the unchanged `FullCopyStrategy` and
`DeltaStrategy`. Stage 12A provenance is extended to field paths. Stage 12C
information-flow enforcement is not implemented.

## Structured paths

`FieldPath` contains an `InferenceState` field name followed by typed `DictKey`
and `ListIndex` components. For example:

```python
FieldPath(
    "session_memory",
    (DictKey("result"), DictKey("rows"), ListIndex(1), DictKey("email")),
)
```

Canonical metadata keys encode types and escape dictionary separators, avoiding
ambiguity between dictionary key `"1"` and list index `1`. There is no string
path parser or external path-expression dependency.

## COW semantics

At begin, `COWContext` holds a reference to committed state and contains no local
copy. Reads return a deep copy for safety; callers cannot mutate committed state
through a returned container. Explicit `read_path`, `write_path`, and
`delete_path` APIs are therefore required for fine-grained behavior.

A write shallow-copies each mutable container along the branch below the
top-level entry. A write to
`profile.authorization.external_sharing` copies `profile` and `authorization`,
not `name` or `preferences`. Transaction-local roots may share unchanged child
objects with committed state because no mutable references to those children are
exposed. Commit assigns only changed roots; rollback discards them.

Nested shared aliases are safe under this rule. Modifying an indexed permission
under `profile_A` copies the `profile_A` dictionary and permission list.
`profile_B` continues to reference the original committed list. The committed
state is not changed until commit, and the alias is broken only on the modified
branch.

Arbitrary callback mutation cannot be intercepted reliably. Calling `mutate()`
materializes a full deep copy, records `full_materialization_occurred=True` and
reason `arbitrary_callback_mutation`, and then runs the callback against that
copy. This preserves compatibility and correctness at the cost of COW savings.

## Field provenance

Stage 12A's side-table now accepts a canonical nested `FieldPath` as its key.
Leaf fields independently reference runtime-issued source IDs. Containers carry
structural meaning only; the runtime does not flatten or automatically union all
child labels into one container label. A policy may explicitly request child
lineage later, but Stage 12B implements no default flow policy.

Writing one leaf replaces provenance only for that path. Sibling labels remain
unchanged. A derived leaf may reference a `DERIVED_VALUE` node with multiple
parents. Deleting a field removes its active path metadata on commit; the
committed registry record remains as audit history. Rollback retains original
field metadata and discards provenance nodes issued by the aborted transaction.

Private state uses field-level COW. Shared state deliberately retains Stage 2's
whole-key integer version conflict granularity. Stage 12B does not claim nested
shared-field conflict detection.

## Flagship correctness experiment

The initial profile contained trusted provenance for `name`, `preferences.editor`,
and `authorization.external_sharing=false`. A retrieved, untrusted source then
proposed setting only `external_sharing=true`.

| Property | Rollback | Commit |
|---|---:|---:|
| committed value before closure | false | false |
| transaction-local value | true | true |
| committed value after closure | false | true |
| structural integrity | pass | pass |
| target provenance | original trusted | new untrusted retrieval |
| name provenance unchanged | yes | yes |
| editor provenance unchanged | yes | yes |
| tentative source discarded | yes | N/A; source committed |
| copied container nodes | 2 | 2 |
| full materialization | no | no |

The rollback state digest exactly matched its pre-transaction digest. The commit
variant changed the target value and provenance without relabeling siblings.

## Benchmark design

The primary synthetic matrix contains 180 cells:

- sizes: 10 KB, 100 KB, 1 MB, 10 MB, and 50 MB;
- mutation ratios: 1%, 5%, 10%, 25%, 50%, and 100%;
- representative nesting depth: 3;
- strategies: FullCopy, Delta, and FineGrainedCOW;
- outcomes: commit and rollback;
- one measured iteration per cell.

Thirty-six additional cells test depths 1 and 5 at 100 KB and mutation ratios
1%, 10%, and 100%. The depth-3 primary matrix already supplies the comparable
depth-3 subset, avoiding a 540-cell Cartesian product. Model generation is absent.

Phases include begin, read, mutation, validation, closure, total latency, and peak
`tracemalloc` allocation. Copy amplification is estimated Python nodes copied per
logically modified leaf. FullCopy counts whole-state copies at begin and commit;
Delta counts branch copies during read/write/commit; COW counts actual shallow
container copies. These are strategy-aware estimates, not byte-accurate allocator
traces.

## Results

The following medians aggregate the 30 primary cells for each strategy/outcome:

| Strategy | Outcome | Total latency | Closure latency | Copy amplification | Integrity | Explicit-path fallback |
|---|---|---:|---:|---:|---:|---:|
| FullCopy | commit | 3.105 ms | 0.870 ms | 43.54 | 30/30 | 0/30 |
| FullCopy | rollback | 2.009 ms | 0.013 ms | 21.77 | 30/30 | 0/30 |
| Delta | commit | 1.361 ms | 0.181 ms | 9.00 | 30/30 | 0/30 |
| Delta | rollback | 1.116 ms | 0.012 ms | 6.00 | 30/30 | 0/30 |
| FineGrainedCOW | commit | 0.708 ms | 0.029 ms | 2.00 | 30/30 | 0/30 |
| FineGrainedCOW | rollback | 0.720 ms | 0.012 ms | 2.00 | 30/30 | 0/30 |

All 216 records reported rollback and provenance integrity. Explicit path
workloads caused 0/216 full materializations. The dedicated callback test caused
1/1 expected full materialization and still restored the exact rollback digest.

COW was faster than Delta in 59 of 60 matched primary strategy/outcome cells.
The negative crossover was the 10 MB, 1% mutation rollback cell: COW total
latency was 0.222 ms versus Delta's 0.204 ms (COW/Delta 1.088). With one iteration
per cell, this point should be treated as an observed local crossover, not a
stable threshold.

For depth-3 mutations, COW copies two containers per modified field. Depth-1
replacement copies no nested container and depth-5 mutation copies four. Path
bookkeeping therefore grows with depth even though it avoids whole-state copying.

## Provenance overhead

In a separate 2,000-iteration Python 3.13.9 microbenchmark, a COW nested-field
mutation without provenance had median time 6,917 ns. Provenance issuance plus
the same mutation measured 18,875 ns, an incremental 11,958 ns (0.011958 ms).
This is consistent with the Stage 12A narrow measurement but is not end-to-end
transaction latency.

## Research questions

- **RQ1:** Exact rollback held in all measured cells and nested correctness tests.
- **RQ2:** Modified leaves received new lineage while sibling provenance remained unchanged in the flagship and list/multi-parent tests.
- **RQ3:** COW reduced median node amplification relative to both existing strategies in this matrix.
- **RQ4:** COW was generally faster here, but lost one sparse 10 MB rollback cell; deeper paths increased copied-chain bookkeeping.
- **RQ5:** Explicit paths materialized 0/216 times; arbitrary callbacks materialized 1/1 times by design.
- **RQ6:** The required alias fixture produced no committed or sibling leakage.

## Trusted-core audit

The Stage 12A frozen mechanism measured 8 modules and 1,646 LOC. Stage 12B
measures 9 modules and 1,958 nonblank/non-comment Python LOC, an increase of one
module and 312 LOC. The added trusted module contains typed paths and COW storage;
benchmark/reporting code is excluded. Third-party runtime dependencies remain zero.

## Limitations

- Measurements use one iteration per matrix cell on one local host.
- `tracemalloc` is not RSS, and copied-byte estimates are approximate.
- Explicit path writes support replacement and deletion, not general list insertion.
- Safe reads deep-copy returned values, so read cost can still scale with the value read.
- Repeated writes to the same deep branch may copy its chain more than once.
- Callback fallback rewrites full private state on commit.
- Field provenance is explicit metadata, not automatic dynamic taint.
- Container provenance is structural; aggregate child queries are not implemented.
- Shared conflict detection remains key-level.
- The runtime remains in-memory, non-durable, single-process, and not thread-safe.

Stage 12C was not started.
