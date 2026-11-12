"""Canonical integrity helpers."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from .runtime import InferenceState


def canonical_state_bytes(state: InferenceState) -> bytes:
    """Serialize JSON-compatible inference state with stable ordering."""
    return json.dumps(
        asdict(state), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def state_digest(state: InferenceState) -> str:
    return hashlib.sha256(canonical_state_bytes(state)).hexdigest()

