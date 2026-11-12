"""Strict model-plan parsing and trusted transactional execution."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from typing import Any

from .effects import EffectManager, PendingEffect, TransactionalTools
from .runtime import TransactionManager
from .model import ModelAdapter


class OperationType(str, Enum):
    MEMORY_READ = "MEMORY_READ"
    MEMORY_WRITE = "MEMORY_WRITE"
    CACHE_READ = "CACHE_READ"
    CACHE_WRITE = "CACHE_WRITE"
    EMAIL_SEND = "EMAIL_SEND"


class Provenance(str, Enum):
    USER_PROMPT = "user_prompt"
    RETRIEVED_CONTENT = "retrieved_content"
    MODEL_GENERATED = "model_generated"
    TOOL_RESULT = "tool_result"


@dataclass(frozen=True)
class ProposedOperation:
    operation_id: str
    operation_type: OperationType
    arguments: dict[str, Any]
    source: Provenance


@dataclass(frozen=True)
class ModelPlan:
    operations: tuple[ProposedOperation, ...]
    final_response: str


class ModelPlanError(ValueError):
    """Fail-closed rejection of malformed, unknown, or unsupported model output."""


_ARGUMENTS = {
    OperationType.MEMORY_READ: {"key": str},
    OperationType.MEMORY_WRITE: {"key": str, "value": object},
    OperationType.CACHE_READ: {"key": str},
    OperationType.CACHE_WRITE: {"key": str, "value": object},
    OperationType.EMAIL_SEND: {"to": str, "subject": str, "body": str},
}


def parse_model_plan(raw_output: str) -> ModelPlan:
    """Parse the complete strict JSON plan before any operation can execute."""
    if not isinstance(raw_output, str):
        raise ModelPlanError("model output must be a string")
    try:
        document = json.loads(raw_output)
    except json.JSONDecodeError as error:
        raise ModelPlanError(f"malformed model output: {error.msg}") from error
    if not isinstance(document, dict) or set(document) != {"operations", "final_response"}:
        raise ModelPlanError("plan requires exactly operations and final_response")
    if not isinstance(document["operations"], list):
        raise ModelPlanError("operations must be a list")
    if not isinstance(document["final_response"], str):
        raise ModelPlanError("final_response must be a string")
    identifiers: set[str] = set()
    operations = tuple(_parse_operation(item, index, identifiers)
                       for index, item in enumerate(document["operations"]))
    return ModelPlan(operations, document["final_response"])


def _parse_operation(raw: Any, index: int,
                     identifiers: set[str]) -> ProposedOperation:
    prefix = f"operation {index}"
    if not isinstance(raw, dict) or set(raw) != {
        "operation_id", "operation_type", "arguments", "source"
    }:
        raise ModelPlanError(f"{prefix} has missing or unsupported fields")
    operation_id = raw["operation_id"]
    if not isinstance(operation_id, str) or not operation_id:
        raise ModelPlanError(f"{prefix} operation_id must be a non-empty string")
    if operation_id in identifiers:
        raise ModelPlanError(f"duplicate operation_id: {operation_id}")
    identifiers.add(operation_id)
    try:
        operation_type = OperationType(raw["operation_type"])
    except (ValueError, TypeError) as error:
        raise ModelPlanError(f"{prefix} has unknown operation type") from error
    try:
        source = Provenance(raw["source"])
    except (ValueError, TypeError) as error:
        raise ModelPlanError(f"{prefix} has unsupported provenance") from error
    arguments = raw["arguments"]
    schema = _ARGUMENTS[operation_type]
    if not isinstance(arguments, dict) or set(arguments) != set(schema):
        raise ModelPlanError(f"{prefix} has invalid arguments")
    for name, expected in schema.items():
        if expected is not object and not isinstance(arguments[name], expected):
            raise ModelPlanError(f"{prefix} argument {name} has invalid type")
    try:
        json.dumps(arguments, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ModelPlanError(f"{prefix} arguments are not JSON-compatible") from error
    return ProposedOperation(operation_id, operation_type, arguments, source)


@dataclass(frozen=True)
class OperationExecution:
    operation_id: str
    value: Any = None
    pending_effect: PendingEffect | None = None


class OperationExecutor:
    """Trusted mapper from validated operations to scoped transaction APIs."""

    def __init__(self, transactions: TransactionManager,
                 effects: EffectManager | None = None) -> None:
        self.transactions = transactions
        self.effects = effects

    def execute(self, plan: ModelPlan, transaction_id: str,
                session_id: str, *,
                runtime_provenance: dict[str, tuple[str, ...]] | None = None,
                ) -> tuple[OperationExecution, ...]:
        authoritative = runtime_provenance or {}
        return tuple(self._execute_one(
            operation, transaction_id, session_id,
            authoritative.get(operation.operation_id, ()),
        )
                     for operation in plan.operations)

    def _execute_one(self, operation: ProposedOperation,
                     transaction_id: str, session_id: str,
                     provenance_ids: tuple[str, ...]) -> OperationExecution:
        args = operation.arguments
        if operation.operation_type is OperationType.MEMORY_READ:
            value = self.transactions.read_private(
                transaction_id, session_id, "session_memory", args["key"])
            return OperationExecution(operation.operation_id, value=value)
        if operation.operation_type is OperationType.MEMORY_WRITE:
            self.transactions.write_private(
                transaction_id, session_id, "session_memory", args["key"],
                args["value"], provenance_ids=provenance_ids)
            return OperationExecution(operation.operation_id)
        if operation.operation_type is OperationType.CACHE_READ:
            value = self.transactions.read_private(
                transaction_id, session_id, "application_cache", args["key"])
            return OperationExecution(operation.operation_id, value=value)
        if operation.operation_type is OperationType.CACHE_WRITE:
            self.transactions.write_private(
                transaction_id, session_id, "application_cache", args["key"],
                args["value"], provenance_ids=provenance_ids)
            return OperationExecution(operation.operation_id)
        if operation.operation_type is OperationType.EMAIL_SEND:
            if self.effects is None:
                raise ModelPlanError("EMAIL_SEND is unsupported without an effect manager")
            pending = TransactionalTools(
                self.effects, transaction_id, session_id
            ).send_email(**args, provenance_ids=provenance_ids)
            return OperationExecution(operation.operation_id, pending_effect=pending)
        raise ModelPlanError(f"unsupported operation: {operation.operation_type}")


class ModelPlanRunner:
    """Obtains, parses, and executes a plan with automatic parse-failure rollback."""

    def __init__(self, adapter: ModelAdapter, executor: OperationExecutor) -> None:
        self.adapter = adapter
        self.executor = executor

    def prepare(self, prompt: str, transaction_id: str, session_id: str, *,
                retrieved_content: str | None = None) -> tuple[
                    ModelPlan, tuple[OperationExecution, ...]
                ]:
        raw_output = self.adapter.generate(
            prompt, retrieved_content=retrieved_content
        )
        try:
            plan = parse_model_plan(raw_output)
        except ModelPlanError:
            self.executor.transactions.rollback(transaction_id)
            raise
        try:
            executions = self.executor.execute(plan, transaction_id, session_id)
        except Exception:
            self.executor.transactions.rollback(transaction_id)
            raise
        return plan, executions
