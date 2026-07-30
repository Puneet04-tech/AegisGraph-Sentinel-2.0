"""Dependency validation result model."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationResult:
    """Result of a dependency validation check.

    Attributes:
        valid: True if the dependency is satisfied, False otherwise.
        service_name: Name of the service being validated.
        reason: Human-readable explanation of the validation outcome.
    """

    valid: bool
    service_name: str
    reason: str
