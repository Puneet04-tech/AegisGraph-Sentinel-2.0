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

    def __init__(
        self,
        registry: ConfigRegistry,
        audit_logger: Optional[Any] = None,
        policy_engine: Optional[Any] = None,
        authorization_engine: Optional[Any] = None,
    ) -> None:
        self.registry = registry
        self.audit_logger = audit_logger
        self.policy_engine = policy_engine
        self.authorization_engine = authorization_engine

    def reload(self, updates: Dict[str, Any], authorization_context: Optional[Any] = None) -> ValidationResult:
        auth_result = self._authorize("config.modify", authorization_context)
        if auth_result is not None and not auth_result.allowed:
            errors = [f"authorization denied reload: {auth_result.reason}"]
            self._audit("config_reload_failed", "warning", updates=list(updates), errors=errors)
            return ValidationResult(valid=False, errors=errors)

        if self.policy_engine is not None:
            policy_result = self.policy_engine.evaluate(
                "config_reload_allowed",
                {
                    "updates": list(updates),
                    "update_count": len(updates),
                    "config_reload_allowed": True,
                },
            )
            if not policy_result.allowed:
                errors = [f"policy denied reload: {policy_result.reason}"]
                self._audit(
                    "policy_violation",
                    "warning",
                    policy=policy_result.policy_name,
                    reason=policy_result.reason,
                    updates=list(updates),
                )
                self._audit("config_reload_failed", "warning", updates=list(updates), errors=errors)
                return ValidationResult(valid=False, errors=errors)

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

    def _authorize(self, permission: str, authorization_context: Optional[Any]) -> Optional[Any]:
        if authorization_context is None or self.authorization_engine is None:
            return None
        role = self._role_from_context(authorization_context)
        return self.authorization_engine.authorize(role, permission)

    @staticmethod
    def _role_from_context(authorization_context: Any) -> str:
        if isinstance(authorization_context, str):
            return authorization_context
        if isinstance(authorization_context, dict):
            return str(authorization_context.get("role", ""))
        return str(getattr(authorization_context, "role", ""))
