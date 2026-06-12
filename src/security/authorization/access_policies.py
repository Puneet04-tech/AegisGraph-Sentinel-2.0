"""Default in-memory authorization registrations."""

from __future__ import annotations

from .permission_registry import PermissionRegistry
from .role_registry import RoleRegistry

DEFAULT_PERMISSIONS = [
    "config.read",
    "config.modify",
    "policy.read",
    "policy.modify",
    "runtime.read",
    "runtime.manage",
    "recovery.execute",
    "recovery.override",
    "resource.read",
    "resource.modify",
    "audit.read",
]


def register_default_access_policies(
    role_registry: RoleRegistry,
    permission_registry: PermissionRegistry,
) -> None:
    for permission in DEFAULT_PERMISSIONS:
        permission_registry.register_permission(permission)

    role_registry.register_role("SUPER_ADMIN", DEFAULT_PERMISSIONS)
    role_registry.register_role(
        "SECURITY_ADMIN",
        ["config.read", "policy.read", "policy.modify", "runtime.read", "audit.read"],
    )
    role_registry.register_role(
        "OPERATIONS_ADMIN",
        ["config.read", "runtime.read", "runtime.manage", "recovery.execute", "resource.read", "resource.modify"],
    )
    role_registry.register_role("READ_ONLY", ["config.read", "policy.read", "runtime.read", "resource.read", "audit.read"])
    role_registry.register_role("SYSTEM_INTERNAL", DEFAULT_PERMISSIONS)
