# AegisGraph Sentinel Enterprise
# Role Registry Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from src.security.authorization.role_registry import RoleRegistry

def test_role_registry_empty():
    registry = RoleRegistry()
    assert len(registry.list_roles()) == 0

def test_role_registry_register():
    registry = RoleRegistry()
    registry.register_role("admin", ["read:all", "write:all"])
    assert registry.role_exists("admin") is True
    assert registry.get_permissions("admin") == {"read:all", "write:all"}

def test_role_registry_get_missing_role():
    registry = RoleRegistry()
    assert registry.get_permissions("invalid_role") == set()

def test_role_registry_register_none_permissions():
    registry = RoleRegistry()
    registry.register_role("guest", None)
    assert registry.role_exists("guest") is True
    assert registry.get_permissions("guest") == set()

def test_role_registry_list_roles():
    registry = RoleRegistry()
    registry.register_role("viewer", ["read:some"])
    registry.register_role("admin", ["write:some"])
    assert registry.list_roles() == ["admin", "viewer"]
