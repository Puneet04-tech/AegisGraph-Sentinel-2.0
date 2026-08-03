"""Dedicated unit tests for src/security/secure_logging.py.

``safe_log_metadata`` and ``safe_log_event`` build sanitized payloads for log
consumers but had no direct unit coverage.  These tests pin the envelope shape
and the redaction of sensitive keys in payload and metadata.
"""

from src.security.secure_logging import safe_log_event, safe_log_metadata


def test_safe_log_metadata_redacts_sensitive_keys():
    result = safe_log_metadata({"password": "hunter2", "user": "alice"})
    assert result["password"] == "[REDACTED]"
    assert result["user"] == "alice"


def test_safe_log_metadata_none_returns_empty():
    assert safe_log_metadata() == {}


def test_safe_log_event_builds_envelope():
    result = safe_log_event("login_failed", payload={"user": "alice"})
    assert result["event_type"] == "login_failed"
    assert result["payload"] == {"user": "alice"}
    assert result["metadata"] == {}


def test_safe_log_event_redacts_payload_and_metadata():
    result = safe_log_event(
        "login_failed",
        payload={"api_key": "abc"},
        metadata={"secret": "xyz"},
    )
    assert result["payload"] == {"api_key": "[REDACTED]"}
    assert result["metadata"] == {"secret": "[REDACTED]"}
