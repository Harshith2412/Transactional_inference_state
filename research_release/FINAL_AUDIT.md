# Stage 12 final audit

Audit date: 2026-08-19. Release candidate: `v0.1.0-rc1`.

## Validation summary

| Check | Result |
|---|---|
| Full suite | 263 passed, 1 skipped, 0 failed in 0.77 s (final run) |
| Test interpreter | Python 3.13.9 |
| PolicyV1 fingerprint | `b9c476b30befcd7ae7a34c0effaee6f991cc84d76d64154d56ee95aba460ffb7` |
| PolicyV2 fingerprint | `ca3702e69066389a46b785e067ad068d34a6401828d0dfc933523216a386962e` |
| Trusted core | 7 modules, 1,210 Python LOC, 0 third-party runtime dependencies |
| Frozen files | 15/15 SHA-256 matches |
| Markdown links | 83 checked, 0 broken |
| Architecture SVG | well-formed XML |
| Abstract | 238 words |
| Manuscript | 3,636 words |

The host default was Python 3.14.3 but lacked pytest. The validated suite used the
installed Python 3.13.9 interpreter. Ollama client 0.32.9 was present; its service
was unavailable during the freeze audit, so no live generation was repeated.

## Commands and evidence

The full suite was run with:

```bash
python3.13 -m pytest -q
```

Policy fingerprints were recomputed with `policy_fingerprint(PolicyV1())` and
`policy_fingerprint(PolicyV2())`. `complexity_report(Path("."))` recomputed the
trusted-core module, LOC, and dependency fields.

`python3 research_release/verify_freeze.py` checked the three Stage 10 corpus
files, three Stage 11 manifests, and nine important result files against the
manifest. All matched after documentation work. This verifies that Stage 10 and
Stage 11 raw result files were not modified.

The following non-live workflows were exercised:

- corpus inventory in the repository (read-only);
- deterministic Stage 7 evaluation in an isolated `/tmp` working tree;
- Stage 10 deterministic regeneration in that isolated tree;
- snapshot-matrix smoke run at `10KB`, one iteration, in that tree;
- deterministic rollback/effect demo in the repository;
- freeze hash verification.

The documented full seven-iteration snapshot command was not rerun because the
smoke run verifies routing while preserved timings are intentionally not replaced.
Stage 11 report generation was not rerun in the repository because it writes
generated artifacts; existing artifacts and links were audited instead. A first
snapshot smoke invocation used unsupported size `1KB` and raised `KeyError`; the
corrected supported `10KB` invocation succeeded. This did not touch frozen data.

## Manuscript evidence audit

The manuscript contains and was checked for the central source-backed values:
Stage 10 70.0% recall and 12.5% FPR; Stage 11 69/75 detection, 6/53 false
rejection, 6/75 persistent compromise, and 69/69 conditional containment;
forced-rejection 57/75 baseline state consequences, 24/75 baseline effects, and
75/75 rollback integrity; and performance values 2.298 s, 0.093 ms, 0.182 ms,
and 0.00461%. Source files report six policy failures and 84 compatible timing
records.

## Claims, links, and data hygiene

The documentation audit found no claim that the runtime provides arbitrary
machine-state rollback or arbitrary external-effect rollback. Existing 100%
figures were already qualified; the new README makes the policy/containment split
and denominators prominent. The architecture and paper use no fabricated
citations; missing literature is marked `[CITATION NEEDED]`.

A pattern scan of the new release and paper material found no private-key block,
API credential, or bearer-token form. Preserved evaluation content uses simulated
secrets and `.test`/example addresses. No live service was contacted during this
audit.
