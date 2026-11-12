import json
from pathlib import Path

import pytest
import transactional_inference_state.stage15a as stage15a
from transactional_inference_state.stage15a_reporting import generate_stage15a_artifacts


def test_service_state_models_and_canonical_digest():
    tool = stage15a.ToolServiceState(); rag = stage15a.RagCacheState()
    assert tool.document() == {"counter": 0, "key_value_store": {"role": "user"}, "history": []}
    assert rag.authorization == "user" and rag.retrieval_cache == {}
    assert tool.digest() == stage15a.canonical_digest(tool.document())


def test_required_mutation_baseline_persists():
    result = stage15a.baseline_experiment()
    assert result["mutation_persists"] and result["before_digest"] != result["after_digest"]
    assert result["mutated"]["tool"]["counter"] == 1
    assert result["mutated"]["tool"]["key_value_store"]["role"] == "admin"
    assert result["mutated"]["rag"]["retrieval_cache"]["poison"] == "approved disclosure"


def test_ci_oracle_exact_restore_is_not_mislabeled_native():
    result = stage15a.simulated_checkpoint_experiment()
    assert result["structural_match"] and all(result["digest_match"].values())
    assert not result["is_native_checkpoint"] and result["backend"] == "IN_MEMORY_TEST_ORACLE"


def test_backend_unavailable_behavior_is_explicit(monkeypatch):
    monkeypatch.setattr(stage15a.platform, "system", lambda: "Darwin")
    probe = stage15a.CommandBackend("CRIU", "criu", ("--version",)).probe()
    assert probe.status is stage15a.BackendStatus.HOST_UNSUPPORTED
    assert probe.suitability is stage15a.Suitability.UNAVAILABLE


def test_external_side_effect_and_filesystem_are_not_rolled_back(tmp_path):
    effect = stage15a.external_side_effect_negative_test(tmp_path / "observer")
    filesystem = stage15a.filesystem_negative_test(tmp_path / "state")
    assert effect["service_restored"] and effect["observer_effect_remains"]
    assert filesystem["memory_restored"] and not filesystem["filesystem_restored"]


def test_failure_injection_never_reports_success():
    rows = stage15a.failure_injection_results()
    assert len(rows) == 5 and all(not row["rollback_reported_successful"] for row in rows)


def test_result_and_artifact_schema(tmp_path):
    result = generate_stage15a_artifacts(tmp_path / "stage15a")
    required = {"environment", "backends", "baseline", "filesystem", "external_effects",
                "performance", "recommendation", "transcript"}
    assert required <= result.keys()
    assert len(list((tmp_path / "stage15a/tables").glob("*.json"))) == 10
    assert len(list((tmp_path / "stage15a/figures").glob("*.svg"))) == 4
    persisted = json.loads((tmp_path / "stage15a/report/stage15a_results.json").read_text())
    assert persisted["schema_version"] == 1


@pytest.mark.checkpoint_backend
@pytest.mark.skipif(stage15a.platform.system() != "Linux", reason="Linux checkpoint host required")
def test_native_checkpoint_backends_are_separate_optional_tests():
    assert all("status" in probe for probe in stage15a.backend_probes())
