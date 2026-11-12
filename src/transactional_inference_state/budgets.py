"""Configurable fail-closed transaction resource budgets."""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from .operations import ModelPlan, OperationType


@dataclass(frozen=True)
class TransactionBudget:
    max_operations_per_tx: int = 50
    max_state_write_bytes: int = 1_048_576
    max_pending_effects: int = 10
    max_nested_depth: int = 20
    max_plan_bytes: int = 262_144
    max_delta_bytes: int = 1_048_576


class ResourceBudgetExceeded(RuntimeError):
    def __init__(self, budget_name: str, observed: int, limit: int) -> None:
        super().__init__(f"{budget_name} exceeded: observed {observed}, limit {limit}")
        self.budget_name, self.observed, self.limit = budget_name, observed, limit


class BudgetEnforcer:
    """Measures raw plans and parsed writes before trusted execution begins."""

    def __init__(self, budget: TransactionBudget | None = None) -> None:
        self.budget = budget or TransactionBudget()

    def check_raw_plan(self, raw_output: str) -> None:
        size = len(raw_output.encode("utf-8"))
        self._limit("max_plan_bytes", size, self.budget.max_plan_bytes)

    def check_plan(self, plan: ModelPlan) -> None:
        self._limit("max_operations_per_tx", len(plan.operations),
                    self.budget.max_operations_per_tx)
        effects = sum(operation.operation_type is OperationType.EMAIL_SEND
                      for operation in plan.operations)
        self._limit("max_pending_effects", effects, self.budget.max_pending_effects)
        write_bytes = 0
        deepest = 0
        for operation in plan.operations:
            deepest = max(deepest, nested_depth(operation.arguments))
            if operation.operation_type in {
                OperationType.MEMORY_WRITE, OperationType.CACHE_WRITE
            }:
                write_bytes += len(json.dumps(
                    operation.arguments["value"], sort_keys=True,
                    separators=(",", ":"), allow_nan=False,
                ).encode("utf-8"))
        self._limit("max_state_write_bytes", write_bytes,
                    self.budget.max_state_write_bytes)
        self._limit("max_delta_bytes", write_bytes, self.budget.max_delta_bytes)
        self._limit("max_nested_depth", deepest, self.budget.max_nested_depth)

    @staticmethod
    def _limit(name: str, observed: int, limit: int) -> None:
        if observed > limit:
            raise ResourceBudgetExceeded(name, observed, limit)


def nested_depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((nested_depth(item) for item in value.values()), default=0)
    if isinstance(value, (list, tuple)):
        return 1 + max((nested_depth(item) for item in value), default=0)
    return 0

