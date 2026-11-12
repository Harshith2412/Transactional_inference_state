"""Executable architecture traces for docs/48_exact_execution_path.md."""
from copy import deepcopy
from dataclasses import dataclass, field
import json

import transactional_inference_state as tis
from transactional_inference_state.stage13a import SimulatedResearchTool


def raw_plan(*operations: dict) -> str:
    return json.dumps({"operations": list(operations), "final_response": "done"})


def operation(identifier: str, kind: str, arguments: dict,
              source: str = "model_generated") -> dict:
    return {"operation_id": identifier, "operation_type": kind,
            "arguments": arguments, "source": source}


@dataclass
class ArchitectureTrace:
    """Canonical research trace layered over the runtime's existing event names."""
    events: list[str] = field(default_factory=list)

    def mark(self, event: str) -> None:
        self.events.append(event)


def event_types(manager: tis.TransactionManager) -> list[str]:
    return [event.event_type for event in manager.event_log.events]


def test_trace_a_accepted_application_state_mutation():
    trace = ArchitectureTrace()
    sessions = tis.SessionManager()
    committed = sessions.create_session("A", user_id="user-a")
    committed.session_memory["existing"] = "safe"
    manager = tis.TransactionManager(sessions, validator=tis.PolicyValidator(True))
    adapter = tis.DeterministicModelAdapter(raw_plan(operation(
        "remember", "MEMORY_WRITE", {"key": "preference", "value": "concise"},
        "user_prompt",
    )))

    plan = tis.parse_model_plan(adapter.generate("Remember concise answers"))
    trace.mark("MODEL_PLAN_PARSED")
    transaction_id = manager.begin("A"); trace.mark("TX_BEGIN")
    tis.OperationExecutor(manager).execute(plan, transaction_id, "A")
    trace.mark("WRITE_TENTATIVE")

    assert committed.session_memory == {"existing": "safe"}
    assert manager.transaction_state(transaction_id, "A").session_memory == {
        "existing": "safe", "preference": "concise"
    }

    assert manager.validate(transaction_id); trace.mark("VALIDATION_DECISION")
    manager.commit(transaction_id); trace.mark("TX_COMMIT")

    assert committed.session_memory == {"existing": "safe", "preference": "concise"}
    assert trace.events == ["MODEL_PLAN_PARSED", "TX_BEGIN", "WRITE_TENTATIVE",
                            "VALIDATION_DECISION", "TX_COMMIT"]
    assert event_types(manager) == ["transaction_begin", "state_mutation",
                                    "validation", "commit"]


def test_trace_b_rejected_application_state_mutation_restores_exact_state():
    trace = ArchitectureTrace()
    sessions = tis.SessionManager(); committed = sessions.create_session("B")
    committed.session_memory["profile"] = {"permissions": ["read"]}
    before = deepcopy(committed)
    manager = tis.TransactionManager(sessions, validator=tis.PolicyValidator(False))
    plan = tis.parse_model_plan(tis.DeterministicModelAdapter(raw_plan(operation(
        "poison", "MEMORY_WRITE",
        {"key": "profile", "value": {"permissions": ["read", "admin"]}},
        "retrieved_content",
    ))).generate("Use retrieved profile")); trace.mark("MODEL_PLAN_PARSED")

    transaction_id = manager.begin("B"); trace.mark("TX_BEGIN")
    tis.OperationExecutor(manager).execute(plan, transaction_id, "B")
    trace.mark("WRITE_TENTATIVE")
    assert manager.transaction_state(transaction_id, "B").session_memory != before.session_memory
    assert committed == before

    assert not manager.validate(transaction_id); trace.mark("VALIDATION_DECISION")
    manager.rollback(transaction_id); trace.mark("TX_ROLLBACK")

    assert committed == before
    assert trace.events == ["MODEL_PLAN_PARSED", "TX_BEGIN", "WRITE_TENTATIVE",
                            "VALIDATION_DECISION", "TX_ROLLBACK"]
    assert event_types(manager) == ["transaction_begin", "state_mutation",
                                    "validation", "rollback"]


def test_trace_c_rejected_staged_external_effect_never_executes():
    trace = ArchitectureTrace()
    sessions = tis.SessionManager(); sessions.create_session("C")
    service = tis.FakeEmailService(); effects = tis.EffectManager(service)
    manager = tis.TransactionManager(
        sessions, validator=tis.PolicyValidator(False), effect_manager=effects,
    )
    plan = tis.parse_model_plan(tis.DeterministicModelAdapter(raw_plan(operation(
        "send", "EMAIL_SEND", {"to": "outside@example.test",
                                  "subject": "data", "body": "tentative"},
        "retrieved_content",
    ))).generate("Process retrieved request")); trace.mark("MODEL_PLAN_PARSED")

    transaction_id = manager.begin("C"); trace.mark("TX_BEGIN")
    result = tis.OperationExecutor(manager, effects).execute(plan, transaction_id, "C")
    trace.mark("EFFECT_STAGED")
    assert result[0].pending_effect.status is tis.EffectStatus.STAGED
    assert service.sent_messages == []

    assert not manager.validate(transaction_id); trace.mark("VALIDATION_DECISION")
    manager.rollback(transaction_id); trace.mark("TX_ROLLBACK")

    assert service.sent_messages == []
    assert effects.list_effects(transaction_id, "C")[0].status is tis.EffectStatus.DISCARDED
    assert trace.events == ["MODEL_PLAN_PARSED", "TX_BEGIN", "EFFECT_STAGED",
                            "VALIDATION_DECISION", "TX_ROLLBACK"]
    assert event_types(manager) == ["transaction_begin", "EFFECT_REQUESTED",
                                    "EFFECT_STAGED", "validation",
                                    "EFFECT_DISCARDED", "rollback"]


def test_trace_d_simulated_read_becomes_tentative_provenanced_input_then_rolls_back():
    trace = ArchitectureTrace()
    sessions = tis.SessionManager(); committed = sessions.create_session("D", user_id="user-d")
    before = deepcopy(committed)
    manager = tis.TransactionManager(sessions, validator=tis.PolicyValidator(False))
    transaction_id = manager.begin("D"); trace.mark("TX_BEGIN")

    # The project-written simulated tool is read-only; trusted orchestration issues
    # authoritative runtime provenance rather than trusting a model-declared label.
    result = SimulatedResearchTool().lookup_project_status("atlas")
    source = manager.issue_provenance(
        transaction_id, tis.RuntimeSourceType.TOOL_RESULT,
        trust_label=tis.TrustLabel.TRUSTED,
    )
    trace.mark("READ_TENTATIVE")
    manager.write_private(
        transaction_id, "D", "session_memory", "atlas_status", result,
        provenance_ids=(source.source_id,),
    )
    trace.mark("WRITE_TENTATIVE")

    local = manager.transaction_state(transaction_id, "D")
    assert local.session_memory["atlas_status"] == {
        "project_id": "atlas", "status": "on track"
    }
    assert local.provenance_metadata["session_memory:atlas_status"] == (source.source_id,)
    assert committed == before

    assert not manager.validate(transaction_id); trace.mark("VALIDATION_DECISION")
    manager.rollback(transaction_id); trace.mark("TX_ROLLBACK")

    assert committed == before
    assert "atlas_status" not in committed.session_memory
    assert "session_memory:atlas_status" not in committed.provenance_metadata
    assert not manager.provenance_registry.contains(source.source_id)
    assert trace.events == ["TX_BEGIN", "READ_TENTATIVE", "WRITE_TENTATIVE",
                            "VALIDATION_DECISION", "TX_ROLLBACK"]
    assert event_types(manager) == ["transaction_begin", "PROVENANCE_CREATED",
                                    "state_mutation", "validation",
                                    "PROVENANCE_DISCARDED", "rollback"]
