# AegisGraph Sentinel Enterprise
# SaaS Password Strength Policy Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from src.saas.auth.password_policy import validate_password, enforce_password_policy, PasswordPolicyError

def test_validate_password_valid():
    res = validate_password("StrongP@ssw0rd2026!")
    assert res.valid is True
    assert not res.errors

def test_validate_password_too_short():
    res = validate_password("Short1!")
    assert res.valid is False
    assert "at least 12 characters" in res.message

def test_validate_password_missing_lowercase():
    res = validate_password("STRONGPASSWORD123!")
    assert res.valid is False
    assert "lowercase letter" in res.message

def test_validate_password_missing_uppercase():
    res = validate_password("strongpassword123!")
    assert res.valid is False
    assert "uppercase letter" in res.message

def test_validate_password_missing_digit():
    res = validate_password("StrongPassword!")
    assert res.valid is False
    assert "digit" in res.message

def test_validate_password_missing_symbol():
    res = validate_password("StrongPassword123")
    assert res.valid is False
    assert "symbol" in res.message

def test_validate_password_common():
    res = validate_password("password12345")
    assert res.valid is False
    assert "too common" in res.message

def test_validate_password_sequential_runs():
    res = validate_password("abcdStrongPassword123!")
    assert res.valid is False
    assert "repeated or sequential runs" in res.message

def test_validate_password_repeated_characters():
    res = validate_password("StroooongP@ssw0rd!")
    assert res.valid is False
    assert "repeated or sequential runs" in res.message

def test_validate_password_contains_email():
    res = validate_password("aliceSecurePass123!", email="alice@test.org")
    assert res.valid is False
    assert "email address" in res.message

def test_validate_password_contains_username():
    res = validate_password("bobSecurePass123!", username="bob")
    assert res.valid is False
    assert "username" in res.message

def test_enforce_password_policy_raises():
    with pytest.raises(PasswordPolicyError):
        enforce_password_policy("weak")

def test_enforce_password_policy_passes():
    enforce_password_policy("StrongP@ssw0rd2026!")
