"""Small validation helpers for runtime configuration entries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .config_schema import ConfigEntry


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)


class ConfigValidator:
    """Validates required values, simple types, and optional callbacks."""

    @staticmethod
    def validate(entry: ConfigEntry) -> ValidationResult:
        errors: List[str] = []

        if entry.required and entry.value is None:
            errors.append(f"{entry.name} is required")

        if entry.value is not None and entry.expected_type is not None:
            if not isinstance(entry.value, entry.expected_type):
                errors.append(
                    f"{entry.name} must be {entry.expected_type.__name__}; "
                    f"got {type(entry.value).__name__}"
                )

        if entry.value is not None and entry.validator is not None:
            try:
                if not entry.validator(entry.value):
                    errors.append(f"{entry.name} failed custom validation")
            except Exception as exc:
                errors.append(f"{entry.name} validator error: {exc}")

        return ValidationResult(valid=not errors, errors=errors)

    @classmethod
    def validate_many(cls, entries: list[ConfigEntry]) -> ValidationResult:
        errors: List[str] = []
        for entry in entries:
            errors.extend(cls.validate(entry).errors)
        return ValidationResult(valid=not errors, errors=errors)
