# Transactional Inference State

## Overview

Transactional Inference State is an experimental Python runtime for studying
whether selected mutable inference and agent state can remain tentative until an
execution passes independent policy validation. Accepted transactions publish
state changes and staged simulated effects; rejected transactions discard them.
Model weights are read-only and outside the transaction.

This is a research prototype, not a production security boundary.

## Motivation

An untrusted model can propose writes to memory, caches, session metadata, or
security-relevant state. Rejecting its final text is too late if those writes have
already persisted. This project places selected state and simulated effects behind
an explicit begin, validate, commit-or-abort lifecycle.

## Architecture

Untrusted input and model text become a strict structured plan. A trusted parser,
runtime-owned provenance, capability/scope policy, transaction manager, snapshot
strategy, and effect buffer mediate the plan. See the
[paper architecture figure](research_release/figures/architecture.svg) and
[trust boundary](TRUST_BOUNDARY.md).

## Quick start

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python3.13 -m pip install -e .
python3.13 -m pip install pytest
python3.13 -m pytest -q
```

The current Stage 12E suite result is `351 passed, 1 skipped, 0 failed`. The
historical Stage 12 research freeze recorded `263 passed, 1 skipped` before the
subsequent provenance development cycle.

## Simple rollback demo

```bash
PYTHONPATH=src python3.13 research_release/demo.py
```

The demonstration proposes a state mutation and simulated email, rejects the
transaction, and reports matching state digests and zero executed effects.

## Deterministic evaluation

```bash
PYTHONPATH=src python3.13 -m transactional_inference_state evaluate corpus
PYTHONPATH=src python3.13 -m transactional_inference_state evaluate deterministic
PYTHONPATH=src python3.13 -m transactional_inference_state evaluate stage10
PYTHONPATH=src python3.13 -m transactional_inference_state benchmark snapshot-matrix --iterations 7
```

Stage 10's frozen 100-malicious/80-benign evaluation measured PolicyV2 recall of
70.0%, false-positive rate of 12.5%, persistent compromise of 30.0%, and benign
completion of 87.5%. PolicyV1 recall was 35.0% with no observed false positives.

## Optional Ollama evaluation

Ollama is optional. The preserved work used `llama3.2:3b` and `qwen3:4b`; only
Llama passed the Stage 11 interface gate. Read [REPRODUCIBILITY.md](REPRODUCIBILITY.md)
before regenerating frozen output files.

```bash
OLLAMA_MODEL=llama3.2:3b python3.13 -m pytest -q -m ollama
PYTHONPATH=src python3.13 -m transactional_inference_state evaluate models \
  --models llama3.2:3b qwen3:4b --trials 5 --malicious-limit 20 --benign-limit 20
```

## Key results

- Llama produced 128/150 valid Stage 11 plans: 75 malicious and 53 benign plans were evaluable.
- PolicyV2 rejected 69/75 compromised plans (92.0%, 95% CI 83.6%–96.3%) and falsely rejected 6/53 benign plans (11.3%).
- Six accepted malicious plans persisted state, an 8.0% rate among evaluable compromised plans. None produced an external effect.
- Among the 69 rejected compromised plans, all 69 were contained in the tested state/effect model. This is conditional containment, not 100% attack prevention.
- Forced rejection yielded 0/75 transactional state consequences and 0/75 effects, versus 57/75 and 24/75 for immediate baseline execution.
- In 84 compatible local timing records, median incremental enforcement was 0.093 ms (P95 0.182 ms) versus median model generation of 2.298 s.

## Repository structure

- `src/transactional_inference_state/`: runtime and evaluation implementation
- `tests/`: deterministic pytest suite and optional Ollama test
- `evaluation_results/`: preserved raw results, tables, and figures
- `docs/`: design and stage documentation
- `research_release/`: freeze manifest, evidence audit, analyses, and checks
- `paper/`: manuscript draft and citation work plan

## Threat model

User input, retrieved content, model output, proposed operations, and tool-derived
content may be adversarial. The parser, runtime provenance, policy, transaction
manager, snapshot strategy, capability enforcement, and effect staging are
trusted. OS/kernel compromise, malicious trusted code, model-weight rollback,
distributed atomicity, and rollback of already executed arbitrary effects are out
of scope.

## Limitations

The application runtime is in-memory and not thread-safe.
Effects are simulated, and internal commit precedes effect execution. The corpora
are handcrafted. PolicyV2 is imperfect, including a 12.5% Stage 10 FPR and six
live indirect-authorization false negatives. One live model qualified; Qwen did
not. Lineage is lightweight, the operation interface is JSON, and timings are
local-hardware dependent. Stage 15B experimentally coordinates rollback with
one explicitly eligible CRIU-checkpointed process on privileged LinuxKit; it
does not provide durable atomicity, filesystem rollback, persistent-connection
transparency, process-tree support, multi-service atomicity, or arbitrary
external-effect rollback.

## Reproducibility

Start with [REPRODUCIBILITY.md](REPRODUCIBILITY.md). Frozen hashes are in
[`FREEZE_MANIFEST.json`](research_release/FREEZE_MANIFEST.json) and can be checked
with `python3 research_release/verify_freeze.py`.

## Research status

Stages 1–11 remain recorded in research release candidate `v0.1.0-rc1`. Stage
12A subsequently added provenance-aware transactions, Stage 12B added typed
nested paths and fine-grained copy-on-write state, Stage 12C added explicit
cross-session information-flow enforcement, Stage 12D added opt-in selective
commit, quarantine, dependency closure, and review, and Stage 12E added delayed
lineage attribution and selective recovery. None changed PolicyV1,
PolicyV2, or transaction lifecycle semantics. See the
[claims/evidence matrix](research_release/CLAIMS_AND_EVIDENCE.md),
[failure analysis](research_release/FAILURE_ANALYSIS.md), and
[manuscript](paper/manuscript.md). The new development result is documented in
[Stage 12A provenance-aware transactions](docs/31_stage12a_provenance_transactions.md).
Stage 12B design and measurements are in
[fine-grained COW state](docs/32_stage12b_fine_grained_cow.md).
Stage 12C is documented in
[cross-session information flow](docs/33_stage12c_cross_session_information_flow.md).
Stage 12D is documented in
[selective commit and quarantine](docs/34_stage12d_selective_commit_quarantine.md).
Stage 12E is documented in
[delayed compromise and recovery](docs/35_stage12e_delayed_compromise_recovery.md).
