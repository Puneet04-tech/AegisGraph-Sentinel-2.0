"""The validation handler must be able to encode any rejected input.

Pydantic echoes the offending value back under an ``input`` key. JSONResponse
encodes with ``allow_nan=False``, so a NaN or infinity in that position used to
raise inside the handler and turn a 422 into a 500.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.exceptions.handlers import _json_safe

ANALYST_KEY = "validation-encoding-test-key"
HEADERS = {"X-API-Key": ANALYST_KEY}

BASE_TRANSACTION = {
    "transaction_id": "TXN-ENCODING-001",
    "source_account": "ACC1000000001",
    "target_account": "ACC1000000002",
    "amount": 5000.0,
    "currency": "INR",
    "mode": "UPI",
    "timestamp": "2026-07-24T10:00:00Z",
}


def _clear_rate_limit_state():
    """Drop accumulated rate limit counters so 429 cannot mask the status code.

    These cases assert on exact statuses, and the global middleware limit is
    shared across the whole suite, so an earlier file can otherwise exhaust the
    window before this one runs.
    """
    from src.api.main import limiter
    from src.api.validators import reset_rate_limiter

    reset_rate_limiter()
    for attribute in ("storage", "_storage"):
        storage = getattr(limiter, attribute, None)
        if storage is None:
            continue
        inner = getattr(storage, "storage", None)
        if inner is not None:
            inner.clear()
        elif hasattr(storage, "clear"):
            storage.clear()


@pytest.fixture(autouse=True)
def _analyst_auth(monkeypatch):
    monkeypatch.setenv(
        "AEGIS_ROLE_ANALYST", hashlib.sha256(ANALYST_KEY.encode()).hexdigest()
    )
    from src.api.security import _invalidate_auth_cache

    _invalidate_auth_cache()
    _clear_rate_limit_state()
    yield
    _invalidate_auth_cache()


# Only NaN and -Infinity fail the gt=0 constraint and therefore reach the
# validation handler. Positive infinity satisfies gt=0, so it is accepted and
# scored rather than rejected, and is covered separately below.
@pytest.mark.parametrize("value", [float("nan"), float("-inf")])
def test_non_finite_amount_is_rejected_with_422(value):
    payload = dict(BASE_TRANSACTION, amount=value)

    response = TestClient(app).post(
        "/api/v1/fraud/check", headers=HEADERS, json=payload
    )

    assert response.status_code == 422, (
        f"a non-finite amount produced {response.status_code} rather than a "
        "validation error, so the handler could not encode its own response"
    )


def test_positive_infinity_amount_does_not_error():
    """Documents current behaviour: +inf satisfies gt=0 and is scored."""
    payload = dict(BASE_TRANSACTION, amount=float("inf"))

    response = TestClient(app).post(
        "/api/v1/fraud/check", headers=HEADERS, json=payload
    )

    assert response.status_code != 500


def test_non_finite_value_inside_a_list_is_rejected_with_422():
    payload = dict(
        BASE_TRANSACTION,
        biometrics={"hold_times": [float("nan")], "flight_times": [1.0]},
    )

    response = TestClient(app).post(
        "/api/v1/fraud/check", headers=HEADERS, json=payload
    )

    assert response.status_code == 422


def test_ordinary_validation_failure_is_unchanged():
    payload = dict(BASE_TRANSACTION, amount=-1.0)

    response = TestClient(app).post(
        "/api/v1/fraud/check", headers=HEADERS, json=payload
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_valid_request_is_unaffected():
    response = TestClient(app).post(
        "/api/v1/fraud/check", headers=HEADERS, json=BASE_TRANSACTION
    )

    assert response.status_code == 200


def test_json_safe_replaces_non_finite_floats():
    payload = {
        "nan": float("nan"),
        "inf": float("inf"),
        "ninf": float("-inf"),
        "nested": [{"deep": float("nan")}],
        "ok": 1.5,
        "text": "unchanged",
    }

    result = _json_safe(payload)

    assert result["nan"] == "NaN"
    assert result["inf"] == "Infinity"
    assert result["ninf"] == "-Infinity"
    assert result["nested"][0]["deep"] == "NaN"
    assert result["ok"] == 1.5
    assert result["text"] == "unchanged"


def test_json_safe_output_is_encodable():
    import json

    encoded = _json_safe({"input": float("nan"), "items": [float("-inf")]})

    assert json.dumps(encoded, allow_nan=False)
