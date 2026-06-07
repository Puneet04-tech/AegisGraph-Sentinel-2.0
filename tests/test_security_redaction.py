from src.security import (
    REDACTED_VALUE,
    is_sensitive_key,
    redact_dict,
    redact_value,
    safe_log_event,
    safe_log_metadata,
    sanitize_metadata,
    sanitize_payload,
    scan_for_secrets,
)


def test_sensitive_key_detection_is_case_insensitive():
    assert is_sensitive_key("API_KEY")
    assert is_sensitive_key("access_token")
    assert is_sensitive_key("client-secret")
    assert not is_sensitive_key("username")


def test_nested_dict_redaction_preserves_normal_fields():
    data = {
        "api_key": "abc123",
        "user": "alice",
        "nested": {"password": "pw", "role": "admin"},
        "none_value": None,
    }

    result = redact_dict(data)

    assert result["api_key"] == REDACTED_VALUE
    assert result["nested"]["password"] == REDACTED_VALUE
    assert result["user"] == "alice"
    assert result["nested"]["role"] == "admin"
    assert result["none_value"] is None


def test_nested_list_redaction_preserves_structure():
    data = {
        "items": [
            {"token": "tok", "id": 1},
            {"details": [{"refresh_token": "rt", "name": "ok"}]},
        ]
    }

    result = redact_value(data)

    assert result["items"][0]["token"] == REDACTED_VALUE
    assert result["items"][0]["id"] == 1
    assert result["items"][1]["details"][0]["refresh_token"] == REDACTED_VALUE
    assert result["items"][1]["details"][0]["name"] == "ok"


def test_scanner_detection_reports_keys_and_count():
    result = scan_for_secrets(
        {
            "authorization": "Bearer abc",
            "nested": [{"connection_string": "postgres://secret"}, {"safe": True}],
        }
    )

    assert result["detected_keys"] == ["authorization", "connection_string"]
    assert result["count"] == 2


def test_metadata_and_payload_sanitizers_use_redaction():
    metadata = sanitize_metadata({"private_key": "key", "module": "runtime"})
    payload = sanitize_payload({"events": [{"bearer": "token", "status": "ok"}]})

    assert metadata == {"private_key": REDACTED_VALUE, "module": "runtime"}
    assert payload["events"][0]["bearer"] == REDACTED_VALUE
    assert payload["events"][0]["status"] == "ok"


def test_safe_logging_helpers_return_sanitized_payloads():
    metadata = safe_log_metadata({"password": "pw", "attempt": 1})
    event = safe_log_event(
        "login",
        {"access_token": "abc", "ok": True},
        metadata={"api_key": "key", "source": "unit"},
    )

    assert metadata == {"password": REDACTED_VALUE, "attempt": 1}
    assert event["payload"] == {"access_token": REDACTED_VALUE, "ok": True}
    assert event["metadata"] == {"api_key": REDACTED_VALUE, "source": "unit"}
