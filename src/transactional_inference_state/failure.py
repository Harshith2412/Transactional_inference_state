"""Deterministic injected failures at named transaction/effect boundaries."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FailurePoint(str, Enum):
    AFTER_BEGIN = "AFTER_BEGIN"
    AFTER_MUTATION = "AFTER_MUTATION"
    AFTER_VALIDATION = "AFTER_VALIDATION"
    DURING_INTERNAL_COMMIT = "DURING_INTERNAL_COMMIT"
    AFTER_INTERNAL_COMMIT = "AFTER_INTERNAL_COMMIT"
    BEFORE_EFFECT_EXECUTION = "BEFORE_EFFECT_EXECUTION"
    DURING_EFFECT_EXECUTION = "DURING_EFFECT_EXECUTION"
    AFTER_FIRST_EFFECT = "AFTER_FIRST_EFFECT"


class InjectedFailure(RuntimeError):
    def __init__(self, point: FailurePoint) -> None:
        super().__init__(f"injected failure at {point.value}")
        self.point = point


@dataclass
class FailureInjector:
    point: FailurePoint
    remaining: int = 1

    def trigger(self, point: FailurePoint) -> None:
        if point is self.point and self.remaining > 0:
            self.remaining -= 1
            raise InjectedFailure(point)

