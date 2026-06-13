"""Minimal fail-safe authorization evaluator."""

from __future__ import annotations

from typing import Iterable, List, Optional

from ...audit import log_audit_event

from .authorization_result import AuthorizationResult
from .permission_registry import PermissionRegistry
from .role_registry import RoleRegistry


class AuthorizationEngine:
    def __init__(
        self,
        role_registry: RoleRegistry,
        permission_registry: PermissionRegistry,
        audit_logger: Optional[object] = log_audit_event,
    ) -> None:
        self.role_registry = role_registry
        self.permission_registry = permission_registry
        self.audit_logger = audit_logger

    def authorize(self, role: str, permission: str) -> AuthorizationResult:
        try:
            result = self._authorize(role, permission)
        except Exception as exc:
            result = AuthorizationResult(False, role, permission, f"authorization failed: {exc}")
        self._audit(result)
        return result

    def authorize_many(self, role: str, permissions: Iterable[str]) -> List[AuthorizationResult]:
        return [self.authorize(role, permission) for permission in permissions]

    def _authorize(self, role: str, permission: str) -> AuthorizationResult:
        if not self.role_registry.role_exists(role):
            return AuthorizationResult(False, role, permission, "role not found")

        rule = self.permission_registry.get_permission(permission)
        if rule is None:
            return AuthorizationResult(False, role, permission, "permission not found")
        if not rule.enabled:
            return AuthorizationResult(False, role, permission, "permission disabled")
        if permission not in self.role_registry.get_permissions(role):
            return AuthorizationResult(False, role, permission, "permission not granted")

        return AuthorizationResult(True, role, permission, "allowed")

    def _audit(self, result: AuthorizationResult) -> None:
        if self.audit_logger is None:
            return
        try:
            self.audit_logger(
                event_type="authorization_allowed" if result.allowed else "authorization_denied",
                severity="info" if result.allowed else "warning",
                source="authorization_engine",
                metadata={
                    "role": result.role,
                    "permission": result.permission,
                    "reason": result.reason,
                },
            )
        except Exception:
            pass
