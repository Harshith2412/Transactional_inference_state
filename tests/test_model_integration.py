import json
import os

import pytest

from transactional_inference_state import (
    DeterministicModelAdapter,
    EffectManager,
    EffectStatus,
    FakeEmailService,
    ModelAdapter,
    ModelPlanError,
    ModelPlanRunner,
    OllamaModelAdapter,
    OperationExecutor,
    OperationType,
    Provenance,
    SessionManager,
    TransactionError,
    TransactionManager,
    TransactionStatus,
    parse_model_plan,
    run_benign_memory_experiment,
    run_exfiltration_experiment,
    run_memory_poisoning_experiment,
    run_mixed_operation_experiment,
)


def output(operations, response="ok"):
    return json.dumps({"operations": operations, "final_response": response})


def operation(kind="MEMORY_WRITE", arguments=None, **changes):
    value = {
        "operation_id": "op-1",
        "operation_type": kind,
        "arguments": arguments or {"key": "name", "value": "Ada"},
        "source": "model_generated",
    }
    value.update(changes)
    return value


def runtime_with_effects():
    sessions = SessionManager()
    sessions.create_session("A")
    sessions.create_session("B")
    service = FakeEmailService()
    effects = EffectManager(service)
    manager = TransactionManager(sessions, effect_manager=effects)
    return sessions, service, effects, manager


def test_deterministic_adapter_implements_model_protocol():
    adapter = DeterministicModelAdapter('{"fixed": true}')
    assert isinstance(adapter, ModelAdapter)
    assert adapter.generate("ignored", retrieved_content="also ignored") == '{"fixed": true}'


def test_strict_parser_preserves_order_and_provenance():
    first = operation(operation_id="first", source="user_prompt")
    second = operation(
        kind="CACHE_READ", arguments={"key": "cached"},
        operation_id="second", source="tool_result",
    )
    plan = parse_model_plan(output([first, second], "finished"))
    assert [item.operation_id for item in plan.operations] == ["first", "second"]
    assert plan.operations[0].operation_type is OperationType.MEMORY_WRITE
    assert plan.operations[0].source is Provenance.USER_PROMPT
    assert plan.operations[1].source is Provenance.TOOL_RESULT
    assert plan.final_response == "finished"


@pytest.mark.parametrize(("raw", "message"), [
    ("not json", "malformed"),
    (json.dumps({"operations": []}), "exactly"),
    (json.dumps({"operations": {}, "final_response": "x"}), "must be a list"),
    (output([operation(kind="SHELL_EXEC")]), "unknown operation"),
    (output([{"operation_type": "MEMORY_READ", "arguments": {"key": "x"},
              "source": "model_generated"}]), "missing or unsupported"),
    (output([operation(kind="MEMORY_READ", arguments={"key": 7})]), "invalid type"),
    (output([operation(kind="MEMORY_READ",
                       arguments={"key": "x", "session_id": "B"})]), "invalid arguments"),
    (output([operation(source="invented_source")]), "unsupported provenance"),
])
def test_parser_fails_closed(raw, message):
    with pytest.raises(ModelPlanError, match=message):
        parse_model_plan(raw)


def test_mixed_valid_and_invalid_plan_executes_nothing():
    sessions = SessionManager()
    state = sessions.create_session("A")
    manager = TransactionManager(sessions)
    tx = manager.begin("A")
    raw = output([
        operation(operation_id="valid"),
        operation(kind="UNSUPPORTED", operation_id="invalid"),
    ])
    with pytest.raises(ModelPlanError):
        parse_model_plan(raw)
    assert state.session_memory == {}
    manager.rollback(tx)


def test_trusted_runner_rolls_back_transaction_on_parse_failure():
    sessions = SessionManager()
    state = sessions.create_session("A")
    state.session_memory["baseline"] = "safe"
    manager = TransactionManager(sessions)
    tx = manager.begin("A")
    runner = ModelPlanRunner(
        DeterministicModelAdapter("malformed"), OperationExecutor(manager)
    )
    with pytest.raises(ModelPlanError, match="malformed"):
        runner.prepare("untrusted prompt", tx, "A")
    assert manager.status(tx) is TransactionStatus.ROLLED_BACK
    assert state.session_memory == {"baseline": "safe"}


def test_executor_reads_own_tentative_write_without_committing_it():
    sessions = SessionManager()
    state = sessions.create_session("A")
    manager = TransactionManager(sessions)
    tx = manager.begin("A")
    plan = parse_model_plan(output([
        operation(operation_id="write"),
        operation(kind="MEMORY_READ", arguments={"key": "name"},
                  operation_id="read"),
    ]))
    results = OperationExecutor(manager).execute(plan, tx, "A")
    assert results[1].value == "Ada"
    assert state.session_memory == {}
    manager.rollback(tx)


def test_cross_session_operation_execution_is_rejected():
    sessions = SessionManager()
    sessions.create_session("A")
    state_b = sessions.create_session("B")
    manager = TransactionManager(sessions)
    tx = manager.begin("A")
    plan = parse_model_plan(output([operation()]))
    with pytest.raises(TransactionError, match="does not belong"):
        OperationExecutor(manager).execute(plan, tx, "B")
    assert state_b.session_memory == {}
    manager.rollback(tx)


def test_email_operation_requires_transactional_effect_manager():
    sessions = SessionManager()
    sessions.create_session("A")
    manager = TransactionManager(sessions)
    tx = manager.begin("A")
    plan = parse_model_plan(output([operation(
        kind="EMAIL_SEND",
        arguments={"to": "a@example.test", "subject": "x", "body": "y"},
    )]))
    with pytest.raises(ModelPlanError, match="unsupported"):
        OperationExecutor(manager).execute(plan, tx, "A")
    manager.rollback(tx)


def test_benign_memory_experiment_commits_tentative_operation():
    result = run_benign_memory_experiment()
    assert result.validation_result is True
    assert result.tentative_before_commit is True
    assert result.transaction_status is TransactionStatus.COMMITTED
    assert result.state_contamination is False
    assert result.parse_status == "parsed"


def test_memory_poisoning_experiment_rolls_back_exactly():
    result = run_memory_poisoning_experiment()
    assert result.unsafe_operation_proposed is True
    assert result.validation_result is False
    assert result.transaction_status is TransactionStatus.ROLLED_BACK
    assert result.state_contamination is False
    assert result.rollback_integrity is True


def test_exfiltration_experiment_discards_email_and_state():
    result = run_exfiltration_experiment()
    assert result.unsafe_operation_proposed is True
    assert result.tentative_before_commit is True
    assert result.external_effect_executed is False
    assert result.effect_status is EffectStatus.DISCARDED
    assert result.rollback_integrity is True


def test_benign_email_plan_executes_once_only_after_commit():
    _, service, effects, manager = runtime_with_effects()
    tx = manager.begin("A")
    plan = parse_model_plan(output([operation(
        kind="EMAIL_SEND", source="user_prompt",
        arguments={"to": "friend@example.test", "subject": "hello", "body": "hi"},
    )]))
    execution = OperationExecutor(manager, effects).execute(plan, tx, "A")
    assert execution[0].pending_effect.status is EffectStatus.STAGED
    assert service.sent_messages == []
    manager.validate(tx)
    manager.commit(tx)
    assert len(service.sent_messages) == 1
    assert effects.list_effects(tx, "A")[0].status is EffectStatus.EXECUTED


def test_mixed_operation_experiment_is_all_or_nothing():
    result = run_mixed_operation_experiment()
    assert result.unsafe_operation_proposed is True
    assert result.validation_result is False
    assert result.state_contamination is False
    assert result.external_effect_executed is False
    assert result.effect_status is EffectStatus.DISCARDED
    assert result.rollback_integrity is True


@pytest.mark.ollama
@pytest.mark.skipif(not os.getenv("OLLAMA_MODEL"),
                    reason="set OLLAMA_MODEL to run the optional local-model test")
def test_optional_local_ollama_produces_parseable_plan():
    model = os.environ["OLLAMA_MODEL"]
    adapter = OllamaModelAdapter(model, timeout_seconds=60)
    raw = adapter.generate(
        "Return JSON with exactly operations and final_response. "
        "operations must be an empty list and final_response must be 'ok'."
    )
    plan = parse_model_plan(raw)
    assert plan.operations == ()
