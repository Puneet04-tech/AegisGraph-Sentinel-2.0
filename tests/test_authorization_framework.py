"""Focused tests for the in-memory runtime authorization framework."""

from __future__ import annotations

from src.runtime import RuntimeState
from src.security.authorization import (
    AuthorizationEngine,
    PermissionRegistry,
    RoleRegistry,
    register_default_access_policies,
)


def _engine() -> AuthorizationEngine:
    roles = RoleRegistry()
    permissions = PermissionRegistry()
    permissions.register_permission("config.modify")
    roles.register_role("ADMIN", ["config.modify"])
    return AuthorizationEngine(roles, permissions, audit_logger=None)


def test_role_registration():
    registry = RoleRegistry()

    registry.register_role("ADMIN", ["config.modify"])

    assert registry.role_exists("ADMIN") is True
    assert registry.get_permissions("ADMIN") == {"config.modify"}
    assert registry.list_roles() == ["ADMIN"]


def test_permission_registration():
    registry = PermissionRegistry()

    rule = registry.register_permission("config.modify", "modify config")

    assert rule.permission == "config.modify"
    assert registry.permission_exists("config.modify") is True
    assert registry.list_permissions() == [rule]


def test_successful_authorization():
    result = _engine().authorize("ADMIN", "config.modify")

    assert result.allowed is True
    assert result.role == "ADMIN"
    assert result.permission == "config.modify"
    assert result.reason == "allowed"


def test_deny_unknown_role():
    result = _engine().authorize("MISSING", "config.modify")

    assert result.allowed is False
    assert result.reason == "role not found"


def test_deny_unknown_permission():
    result = _engine().authorize("ADMIN", "missing.permission")

    assert result.allowed is False
    assert result.reason == "permission not found"


def test_deny_disabled_permission():
    roles = RoleRegistry()
    permissions = PermissionRegistry()
    permissions.register_permission("config.modify", enabled=False)
    roles.register_role("ADMIN", ["config.modify"])
    engine = AuthorizationEngine(roles, permissions, audit_logger=None)

    result = engine.authorize("ADMIN", "config.modify")

    assert result.allowed is False
    assert result.reason == "permission disabled"


def test_authorize_many():
    roles = RoleRegistry()
    permissions = PermissionRegistry()
    permissions.register_permission("config.read")
    permissions.register_permission("config.modify")
    roles.register_role("ADMIN", ["config.read"])
    engine = AuthorizationEngine(roles, permissions, audit_logger=None)

    results = engine.authorize_many("ADMIN", ["config.read", "config.modify"])

    assert [result.allowed for result in results] == [True, False]
    assert [result.reason for result in results] == ["allowed", "permission not granted"]


def test_default_policy_registration():
    roles = RoleRegistry()
    permissions = PermissionRegistry()

    register_default_access_policies(roles, permissions)

    assert roles.list_roles() == [
        "OPERATIONS_ADMIN",
        "READ_ONLY",
        "SECURITY_ADMIN",
        "SUPER_ADMIN",
        "SYSTEM_INTERNAL",
    ]
    assert permissions.permission_exists("config.modify") is True
    assert permissions.permission_exists("audit.read") is True


def test_runtime_integration_metrics():
    state = RuntimeState()
    metrics = state.get_metrics()

    assert state.get_service("role_registry") is state.role_registry
    assert state.get_service("permission_registry") is state.permission_registry
    assert state.get_service("authorization_engine") is state.authorization_engine
    assert metrics["authorization"]["role_count"] == 5
    assert metrics["authorization"]["permission_count"] == 11
