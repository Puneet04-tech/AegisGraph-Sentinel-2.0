"""Dedicated unit tests for src/observability/structured_logger.py.

``StructuredLogger`` emits JSON log lines with request/correlation context and
sanitized metadata.  These tests pin the JSON envelope, metadata redaction and
request-context propagation via an injected recording Python logger.
"""

import json

import pytest

from src.observability.structured_logger import (
    StructuredLogger,
    clear_request_context,
    generate_request_id,
    get_correlation_id,
    get_request_id,
    set_request_context,
)


class _RecordingPyLogger:
    def __init__(self) -> None:
        self.records: list = []

    def log(self, level, line) -> None:
        self.records.append((level, line))


@pytest.fixture
def logger() -> StructuredLogger:
    structured = StructuredLogger("testmod")
    structured._logger = _RecordingPyLogger()
    return structured


def test_generate_request_id_format():
    request_id = generate_request_id()
    assert request_id.startswith("req_")
    assert len(request_id) == 16


def test_info_emits_structured_json(logger):
    logger.info("hello", event_type="greeting", metadata={"user": "alice"})
    parsed = json.loads(logger._logger.records[0][1])
    assert parsed["module"] == "testmod"
    assert parsed["severity"] == "INFO"
    assert parsed["event_type"] == "greeting"
    assert parsed["message"] == "hello"
    assert parsed["metadata"]["user"] == "alice"


def test_info_redacts_sensitive_metadata(logger):
    logger.info("login", metadata={"password": "hunter2"})
    parsed = json.loads(logger._logger.records[0][1])
    assert parsed["metadata"]["password"] == "[REDACTED]"


def test_request_context_propagates_into_records(logger):
    tokens = set_request_context(request_id="req_abc123", correlation_id="corr-1")
    try:
        assert get_request_id() == "req_abc123"
        assert get_correlation_id() == "corr-1"
        logger.info("ctx", event_type="ctx")
        parsed = json.loads(logger._logger.records[0][1])
        assert parsed["request_id"] == "req_abc123"
        assert parsed["correlation_id"] == "corr-1"
    finally:
        clear_request_context(tokens)


def test_clear_request_context_resets():
    set_request_context(request_id="req_x")
    clear_request_context()
    assert get_request_id() is None
