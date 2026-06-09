"""Safe dynamic configuration reload manager."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .config_registry import ConfigRegistry
from .config_schema import ConfigEntry
from .config_validator import ConfigValidator, ValidationResult

logger = logging.getLogger(__name__)


class ConfigReloadManager:
    """Validates and atomically applies proposed in-memory updates."""

    def __init__(self, registry: ConfigRegistry, audit_logger: Optional[Any] = None) -> None:
        self.registry = registry
        self.audit_logger = audit_logger

    def reload(self, updates: Dict[str, Any]) -> ValidationResult:
        proposed = []
        errors = []

        for name, value in updates.items():
            if not self.registry.exists(name):
                errors.append(f"{name} is not registered")
                continue

            current = self.registry.get_entry(name)
            current.value = value
            proposed.append(current)

        result = ConfigValidator.validate_many(proposed)
        errors.extend(result.errors)
        result = ValidationResult(valid=not errors, errors=errors)
        if not result.valid:
            self._audit("config_validation_failed", "warning", updates=list(updates), errors=result.errors)
            self._audit("config_reload_failed", "warning", updates=list(updates), errors=result.errors)
            return result

        previous = {name: self.registry.get(name) for name in updates if self.registry.exists(name)}
        try:
            for name, value in updates.items():
                if not self.registry.exists(name):
                    raise KeyError(f"{name} is not registered")
                self.registry.update(name, value)
        except Exception as exc:
            self.registry._restore_values(previous)
            errors = [f"reload failed: {exc}"]
            self._audit("config_reload_failed", "error", updates=list(updates), errors=errors)
            return ValidationResult(valid=False, errors=errors)

        self._audit("config_reload_success", "info", updates=list(updates))
        return ValidationResult(valid=True, errors=[])

    def _audit(self, event_type: str, severity: str, **metadata: Any) -> None:
        if self.audit_logger is None:
            return
        try:
            self.audit_logger(
                event_type=event_type,
                severity=severity,
                source="config_reload",
                metadata=metadata,
            )
        except Exception:
            logger.debug("Configuration audit recording failed", exc_info=True)
