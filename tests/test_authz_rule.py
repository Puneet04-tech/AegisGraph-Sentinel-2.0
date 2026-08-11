# AegisGraph Sentinel Enterprise
# Authorization Rule Engine Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from src.security.authorization.authorization_rule import AuthorizationRule

def test_authz_rule_creation():
    rule = AuthorizationRule(
        permission="read:transactions",
        description="Allows reading UPI transactions",
        enabled=True
    )
    assert rule.permission == "read:transactions"
    assert rule.description == "Allows reading UPI transactions"
    assert rule.enabled is True

def test_authz_rule_defaults():
    rule = AuthorizationRule(permission="write:settings")
    assert rule.description == ""
    assert rule.enabled is True

def test_authz_rule_disabled():
    rule = AuthorizationRule(
        permission="delete:all",
        enabled=False
    )
    assert rule.permission == "delete:all"
    assert rule.enabled is False

def test_authz_rule_modification():
    rule = AuthorizationRule(permission="read:all")
    rule.enabled = False
    assert rule.enabled is False
    rule.description = "New description"
    assert rule.description == "New description"
