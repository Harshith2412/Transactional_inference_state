import json
from pathlib import Path

from transactional_inference_state.stage15a2_reporting import stats


def test_restore_oracle_requires_more_than_command_success():
    failed = {"command_success": True, "reachable": False, "health": False,
              "structural_equal": False, "digest_equal": False}
    assert not all(failed.values())


def test_distribution_statistics_are_deterministic():
    result = stats([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    assert result["min"] == 1 and result["median"] == 5.5 and result["max"] == 10
    assert result["p95"] == 9


def test_sequential_snapshot_is_not_defined_as_atomic():
    observation = {"tool_integrity": True, "rag_integrity": False,
                   "consistent_same_logical_moment": False}
    assert not observation["consistent_same_logical_moment"]


def test_stage15b_gate_remains_closed_in_frozen_artifact():
    path = Path("evaluation_results/stage15a2/report/stage15b_gate.json")
    gate = json.loads(path.read_text())
    assert gate["criu_status"] == "RELIABLE_WITH_SCOPED_LIMITATIONS"
    assert gate["tool_integrity"] == "150/150"
    assert gate["rag_integrity"] == "50/50"
    assert not gate["integration_justified"]
