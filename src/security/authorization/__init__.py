"""Small in-memory runtime authorization framework."""

from .access_policies import DEFAULT_PERMISSIONS, register_default_access_policies
from .authorization_engine import AuthorizationEngine
from .authorization_result import AuthorizationResult
from .authorization_rule import AuthorizationRule
from .permission_registry import PermissionRegistry
from .role_registry import RoleRegistry

__all__ = [
    "AuthorizationEngine",
    "AuthorizationResult",
    "AuthorizationRule",
    "DEFAULT_PERMISSIONS",
    "PermissionRegistry",
    "RoleRegistry",
    "register_default_access_policies",
]
