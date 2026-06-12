"""Thread-safe in-memory permission registry."""

from __future__ import annotations

from threading import RLock
from typing import Dict, List, Optional

from .authorization_rule import AuthorizationRule


class PermissionRegistry:
    def __init__(self) -> None:
        self._permissions: Dict[str, AuthorizationRule] = {}
        self._lock = RLock()

    def register_permission(
        self,
        permission: str,
        description: str = "",
        enabled: bool = True,
    ) -> AuthorizationRule:
        rule = AuthorizationRule(permission=permission, description=description, enabled=enabled)
        with self._lock:
            self._permissions[permission] = rule
            return rule

    def permission_exists(self, permission: str) -> bool:
        with self._lock:
            return permission in self._permissions

    def get_permission(self, permission: str) -> Optional[AuthorizationRule]:
        with self._lock:
            return self._permissions.get(permission)

    def list_permissions(self) -> List[AuthorizationRule]:
        with self._lock:
            return list(self._permissions.values())
