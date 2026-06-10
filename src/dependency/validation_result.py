"""Dependency validation result model."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    service_name: str
    reason: str
