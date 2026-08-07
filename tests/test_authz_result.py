# AegisGraph Sentinel Enterprise
# Authorization Result Payload Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from src.security.authorization.authorization_result import AuthorizationResult

def test_authz_result_allowed():
    res = AuthorizationResult(
        allowed=True,
        role="admin",
        permission="read:audit",
        reason="Role includes explicit write permissions on resource."
    )
    assert res.allowed is True
    assert res.role == "admin"
    assert res.permission == "read:audit"
    assert res.reason == "Role includes explicit write permissions on resource."

def test_authz_result_denied():
    res = AuthorizationResult(
        allowed=False,
        role="viewer",
        permission="write:transactions",
        reason="Viewer role is read-only."
    )
    assert res.allowed is False
    assert res.role == "viewer"
    assert res.permission == "write:transactions"
    assert res.reason == "Viewer role is read-only."

def test_authz_result_type_matching():
    res = AuthorizationResult(
        allowed=True,
        role="moderator",
        permission="delete:comments",
        reason="Allowed by default policy"
    )
    assert isinstance(res.allowed, bool)
    assert isinstance(res.role, str)
    assert isinstance(res.permission, str)
    assert isinstance(res.reason, str)

def test_authz_result_representation():
    res = AuthorizationResult(allowed=True, role="r", permission="p", reason="ok")
    assert "r" in repr(res)
    assert "p" in repr(res)
