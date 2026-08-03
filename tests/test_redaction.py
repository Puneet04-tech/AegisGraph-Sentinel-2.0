"""Dedicated unit tests for src/security/redaction.py.

``redact_value`` / ``redact_dict`` recursively replace sensitive values with
``[REDACTED]`` while preserving structure, but had no direct unit coverage.
These tests pin the redaction rules across scalars, mappings, lists, tuples and
None inputs.
"""

from src.security.redaction import REDACTED_VALUE, redact_dict, redact_value


def test_redact_dict_replaces_sensitive_values():
    data = {"username": "alice", "password": "hunter2", "api_key": "abc123"}
    redacted = redact_dict(data)
    assert redacted["username"] == "alice"
    assert redacted["password"] == REDACTED_VALUE
    assert redacted["api_key"] == REDACTED_VALUE


def test_redact_value_recurses_into_nested_dicts():
    data = {"meta": {"password": "secret", "email": "a@b.com"}}
    assert redact_value(data) == {"meta": {"password": REDACTED_VALUE, "email": "a@b.com"}}


def test_redact_value_handles_lists_of_dicts():
    data = [{"token": "t0k3n"}, {"name": "ok"}]
    assert redact_value(data) == [{"token": REDACTED_VALUE}, {"name": "ok"}]


def test_redact_value_handles_tuples():
    data = ("password", "keep")
    assert redact_value(data) == ("password", "keep")


def test_redact_value_passthrough_for_scalars():
    assert redact_value("hello") == "hello"
    assert redact_value(42) == 42
    assert redact_value(None) is None


def test_redact_dict_none_returns_empty():
    assert redact_dict(None) == {}
