"""Dedicated unit tests for src/security/secrets.py.

``is_sensitive_key`` is the centralized gate used by log sanitization and
redaction, but had no direct unit coverage.  These tests pin the exact
sensitive field-name set, the single-token substring rules and key
normalization.
"""

import pytest

from src.security.secrets import is_sensitive_key


@pytest.mark.parametrize(
    "key",
    [
        "api_key",
        "token",
        "access_token",
        "refresh_token",
        "password",
        "secret",
        "private_key",
        "authorization",
        "bearer",
        "connection_string",
        "client_secret",
        "access_token_encrypted",
    ],
)
def test_sensitive_keys_detected(key):
    assert is_sensitive_key(key) is True


@pytest.mark.parametrize(
    "key",
    ["username", "email", "user_id", "created_at", "amount", "email_address", "status"],
)
def test_non_sensitive_keys_allowed(key):
    assert is_sensitive_key(key) is False


def test_keys_are_case_and_separator_insensitive():
    assert is_sensitive_key("API_KEY") is True
    assert is_sensitive_key("api key") is True
    assert is_sensitive_key("  Token  ") is True
    assert is_sensitive_key("Connection-String") is True
