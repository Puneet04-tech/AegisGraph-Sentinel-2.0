"""Dedicated unit tests for src/security/sanitizers.py.

The sanitizer helpers wrap redaction for structured-log metadata, payloads and
exception context but had no direct unit coverage.  These tests pin the
sanitization behavior for nested sensitive data and None inputs.
"""

from src.security.sanitizers import (
    sanitize_exception_context,
    sanitize_metadata,
    sanitize_payload,
)


def test_sanitize_metadata_redacts_sensitive_keys():
    result = sanitize_metadata({"user": "alice", "password": "hunter2"})
    assert result["user"] == "alice"
    assert result["password"] == "[REDACTED]"


def test_sanitize_payload_redacts_nested_values():
    result = sanitize_payload({"nested": {"token": "abc"}})
    assert result["nested"]["token"] == "[REDACTED]"


def test_sanitize_exception_context_redacts_recursively():
    result = sanitize_exception_context({"context": {"api_key": "key-1"}})
    assert result["context"]["api_key"] == "[REDACTED]"


def test_sanitizers_handle_none_input():
    assert sanitize_metadata() == {}
    assert sanitize_payload() == {}
    assert sanitize_exception_context() == {}
