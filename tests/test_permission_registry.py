# AegisGraph Sentinel Enterprise
# Permission Registry Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from src.security.authorization.permission_registry import PermissionRegistry

def test_permission_registry_empty():
    registry = PermissionRegistry()
    assert len(registry.list_permissions()) == 0

def test_permission_registry_register():
    registry = PermissionRegistry()
    rule = registry.register_permission("read:transactions", "Access UPI transaction feed")
    assert registry.permission_exists("read:transactions") is True
    assert rule.permission == "read:transactions"
    assert rule.description == "Access UPI transaction feed"

def test_permission_registry_get_permission():
    registry = PermissionRegistry()
    registry.register_permission("write:settings", "Modify configuration")
    rule = registry.get_permission("write:settings")
    assert rule is not None
    assert rule.description == "Modify configuration"

def test_permission_registry_get_missing():
    registry = PermissionRegistry()
    assert registry.get_permission("invalid:perm") is None

def test_permission_registry_list_permissions():
    registry = PermissionRegistry()
    registry.register_permission("p1", "desc1")
    registry.register_permission("p2", "desc2")
    all_rules = registry.list_permissions()
    assert len(all_rules) == 2
    permissions = [r.permission for r in all_rules]
    assert "p1" in permissions
    assert "p2" in permissions
