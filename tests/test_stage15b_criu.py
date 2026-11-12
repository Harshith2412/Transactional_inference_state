"""Opt-in tests: run only inside the privileged Stage 15 Linux container."""
import os
from pathlib import Path

import pytest

from transactional_inference_state.stage15b_linux_runner import accepted, rejected, restore_failure


pytestmark = [
    pytest.mark.checkpoint_backend,
    pytest.mark.skipif(os.environ.get("TIS_RUN_CRIU") != "1", reason="set TIS_RUN_CRIU=1 in privileged Linux"),
]


def test_native_tool_and_rag_rollback(tmp_path: Path):
    for kind, port in (("tool", 19610), ("rag", 19611)):
        result = rejected(kind, port, tmp_path)
        assert result["status"] == "rolled_back"
        assert result["local_restored"] and result["external_restored"] and result["digest_match"]


def test_native_commit_and_restore_failure(tmp_path: Path):
    commit = accepted(19612, tmp_path)
    assert commit["status"] == "committed" and commit["external_preserved"] and commit["checkpoint_released"]
    failure = restore_failure(19613, tmp_path)
    assert failure["status"] == "external_rollback_failed"
    assert failure["local_rollback"] and failure["external_rollback"] is False and failure["checkpoint_retained"]
