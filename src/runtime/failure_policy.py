"""Runtime failure policy helpers."""

from __future__ import annotations

from dataclasses import dataclass


VALID_FAILURE_MODES = {"fail_fast", "degraded", "maintenance"}


def normalize_failure_mode(value: str | None) -> str:
    """Normalize a configured failure mode, defaulting to degraded."""
    if value is None:
        return "degraded"
    normalized = str(value).strip().lower()
    if normalized not in VALID_FAILURE_MODES:
        raise ValueError(
            "runtime failure_mode must be one of: fail_fast, degraded, maintenance"
        )
    return normalized


def should_fail_fast(failure_mode: str) -> bool:
    return failure_mode == "fail_fast"


def should_allow_degraded(failure_mode: str) -> bool:
    return failure_mode in {"degraded", "maintenance"}


@dataclass(frozen=True)
class RuntimeFailurePolicy:
    mode: str = "degraded"

    @property
    def is_fail_fast(self) -> bool:
        return self.mode == "fail_fast"

    @property
    def is_degraded(self) -> bool:
        return self.mode == "degraded"

    @property
    def is_maintenance(self) -> bool:
        return self.mode == "maintenance"

