"""Thread-safe in-memory role registry."""

from __future__ import annotations

from threading import RLock
from typing import Dict, Iterable, List, Set


class RoleRegistry:
    def __init__(self) -> None:
        self._roles: Dict[str, Set[str]] = {}
        self._lock = RLock()

    def register_role(self, role: str, permissions: Iterable[str] | None = None) -> None:
        with self._lock:
            self._roles[role] = set(permissions or ())

    def role_exists(self, role: str) -> bool:
        with self._lock:
            return role in self._roles

    def get_permissions(self, role: str) -> Set[str]:
        with self._lock:
            return set(self._roles.get(role, set()))

    def list_roles(self) -> List[str]:
        with self._lock:
            return sorted(self._roles)
