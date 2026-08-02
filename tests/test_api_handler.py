"""Unit tests for utils.api_handler error-handling and logging helpers."""

import logging

import pytest
from unittest.mock import patch

from utils.api_handler import (
    APIClient,
    APILogger,
    APIError,
    handle_api_call,
    safe_api_call,
    validate_api_response,
)


# ---------------------------------------------------------------------------
# validate_api_response
# ---------------------------------------------------------------------------

def test_validate_api_response_ok() -> None:
    assert validate_api_response({"id": 1, "name": "x"}, ["id", "name"]) is True


def test_validate_api_response_missing_field() -> None:
    with pytest.raises(APIError, match="missing required fields"):
        validate_api_response({"id": 1}, ["id", "name"])


def test_validate_api_response_none_response() -> None:
    with pytest.raises(APIError, match="API response is None"):
        validate_api_response(None, ["id"])


def test_validate_api_response_non_dict() -> None:
    with pytest.raises(APIError, match="not a dictionary"):
        validate_api_response([1, 2], ["id"])


def test_validate_api_response_single_field_as_string() -> None:
    # A single field passed as a plain string must not be iterated by character.
    assert validate_api_response({"id": 1}, "id") is True
    with pytest.raises(APIError, match="missing required fields"):
        validate_api_response({}, "id")


def test_validate_api_response_none_required() -> None:
    assert validate_api_response({"id": 1}, None) is True
    assert validate_api_response({"id": 1}, []) is True


# ---------------------------------------------------------------------------
# handle_api_call decorator
# ---------------------------------------------------------------------------

@handle_api_call(endpoint="test-endpoint")
def _returns_value():
    return {"ok": True}


@handle_api_call(endpoint="test-endpoint", raise_on_error=False, default_return="fallback")
def _returns_none():
    return None


@handle_api_call(endpoint="test-endpoint")
def _returns_none_raises():
    return None


@handle_api_call(endpoint="test-endpoint")
def _raises():
    raise ValueError("boom")


@handle_api_call(endpoint="test-endpoint", raise_on_error=False, default_return="fallback")
def _raises_swallowed():
    raise ValueError("boom")


def test_handle_api_call_success() -> None:
    assert _returns_value() == {"ok": True}


def test_handle_api_call_none_with_raise() -> None:
    with pytest.raises(APIError, match="returned None"):
        _returns_none_raises()


def test_handle_api_call_none_with_default() -> None:
    assert _returns_none() == "fallback"


def test_handle_api_call_exception_raises() -> None:
    with pytest.raises(APIError, match="API call failed: boom"):
        _raises()


def test_handle_api_call_exception_swallowed() -> None:
    assert _raises_swallowed() == "fallback"


def test_handle_api_call_preserves_wrapped_function_name() -> None:
    assert _returns_value.__name__ == "_returns_value"


# ---------------------------------------------------------------------------
# safe_api_call
# ---------------------------------------------------------------------------

def test_safe_api_call_success() -> None:
    assert safe_api_call(lambda: {"ok": 1}) == {"ok": 1}


def test_safe_api_call_none_result() -> None:
    assert safe_api_call(lambda: None) is None


def test_safe_api_call_exception() -> None:
    def _fail():
        raise RuntimeError("nope")

    assert safe_api_call(_fail) is None


# ---------------------------------------------------------------------------
# APILogger
# ---------------------------------------------------------------------------

def test_apilogger_logs_request(caplog) -> None:
    with caplog.at_level(logging.INFO):
        APILogger.log_request("/users", "GET", {"page": 2})
    assert any("API Request: GET /users" in r.message for r in caplog.records)


def test_apilogger_logs_request_no_params(caplog) -> None:
    with caplog.at_level(logging.INFO):
        APILogger.log_request("/users", "GET")
    assert any("no params" in r.message for r in caplog.records)


def test_apilogger_logs_response(caplog) -> None:
    with caplog.at_level(logging.INFO):
        APILogger.log_response("/users", 200, 128)
    assert any("Status 200 - Size 128 bytes" in r.message for r in caplog.records)


def test_apilogger_logs_error(caplog) -> None:
    with caplog.at_level(logging.ERROR):
        APILogger.log_error("/users", ValueError("bad"))
    assert any("API Error at /users" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# APIClient
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code, json_data, content=b""):
        self.status_code = status_code
        self._json = json_data
        self.content = content

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._json


@patch("requests.request", return_value=FakeResponse(200, {"id": 1}, b"{}"))
def test_api_client_get(mock_request) -> None:
    client = APIClient("https://api.example.com")
    result = client.get("users", params={"page": 1})
    assert result == {"id": 1}
    mock_request.assert_called_once()
    kwargs = mock_request.call_args
    assert kwargs.kwargs["timeout"] == 30
    assert "users" in kwargs.kwargs["url"]
    assert kwargs.kwargs["method"] == "GET"
    assert kwargs.kwargs["params"] == {"page": 1}


@patch("requests.request", return_value=FakeResponse(200, {"created": True}))
def test_api_client_post(mock_request) -> None:
    client = APIClient("https://api.example.com")
    result = client.post("users", json={"name": "x"})
    assert result == {"created": True}


@patch("requests.request", side_effect=RuntimeError("timeout"))
def test_api_client_http_error_raises_api_error(mock_request) -> None:
    client = APIClient("https://api.example.com")
    with pytest.raises(APIError, match="API request failed"):
        client.get("users")


@patch("requests.request", return_value=FakeResponse(500, {}, b""))
def test_api_client_bad_status_raises_api_error(mock_request) -> None:
    client = APIClient("https://api.example.com", timeout=5)
    with pytest.raises(APIError, match="API request failed"):
        client.get("users")
