"""Per-endpoint rate limits must not share one counter.

``StrictRateLimit`` is configured with a different budget per route, but the
counters live in one LRU keyed by client identity. Without a scope in the key,
requests to a generous endpoint increment the same counter a stricter endpoint
checks, so the stricter one rejects a caller who never used it.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.security import _invalidate_auth_cache
from src.api.validators import StrictRateLimit, get_rate_limiter, reset_rate_limiter

API_KEY = "rate-limit-scope-test-key"

# Both are POST /api/v1 routes gated by StrictRateLimit with different budgets.
GENEROUS = "/api/v1/fraud/check"      # ip_limit=60
STRICT = "/api/v1/voice/analyze"      # ip_limit=5


@pytest.fixture(autouse=True)
def _clean_limiter(monkeypatch):
    digest = hashlib.sha256(API_KEY.encode()).hexdigest()
    for role in ("ANALYST", "ADMIN", "AUDITOR", "VIEWER", "SUPER_ADMIN"):
        monkeypatch.setenv(f"AEGIS_ROLE_{role}", digest)
    _invalidate_auth_cache()
    reset_rate_limiter()
    yield
    reset_rate_limiter()
    _invalidate_auth_cache()


def _transaction(index):
    return {
        "transaction_id": f"RLS{index}",
        "source_account": f"ACCRL{index:08d}",
        "target_account": f"ACCRT{index:08d}",
        "amount": 1000,
        "currency": "INR",
        "mode": "UPI",
        "timestamp": "2026-07-27T10:00:00Z",
    }


VOICE = {"transaction_id": "RLSV", "audio_features": {}, "audio_base64": ""}


def test_traffic_to_one_endpoint_does_not_exhaust_another():
    client = TestClient(app)
    headers = {"X-API-Key": API_KEY}

    for index in range(6):
        response = client.post(GENEROUS, headers=headers, json=_transaction(index))
        assert response.status_code == 200, (
            f"{GENEROUS} allows 60 per minute but rejected request "
            f"{index + 1} with {response.status_code}"
        )

    response = client.post(STRICT, headers=headers, json=VOICE)

    assert response.status_code != 429, (
        f"the first ever call to {STRICT} was rate limited because 6 calls to "
        f"{GENEROUS} had already consumed its budget. The two endpoints share "
        "one counter keyed only by client IP."
    )


def test_an_endpoint_still_enforces_its_own_limit():
    """Scoping the key must not stop a single endpoint from limiting itself."""
    client = TestClient(app)
    headers = {"X-API-Key": API_KEY}
    statuses = [
        client.post(STRICT, headers=headers, json=VOICE).status_code
        for _ in range(7)
    ]

    assert 429 in statuses, (
        f"{STRICT} allows 5 per minute per IP but 7 consecutive calls produced "
        f"{statuses}, so its own limit is no longer enforced"
    )


def test_counter_keys_carry_the_route_scope():
    client = TestClient(app)
    headers = {"X-API-Key": API_KEY}

    client.post(GENEROUS, headers=headers, json=_transaction(99))
    keys = list(get_rate_limiter().ip_requests)

    assert keys, "the IP bucket recorded nothing"
    assert all(GENEROUS in key for key in keys), (
        f"IP counter keys {keys} do not name the route, so every endpoint "
        "shares one counter"
    )


def test_scope_defaults_to_the_route_path_and_can_be_overridden():
    class _Route:
        path = "/api/v1/example"

    class _Request:
        scope = {"route": _Route()}

    assert StrictRateLimit(ip_limit=1)._scope_for(_Request()) == "/api/v1/example"
    assert (
        StrictRateLimit(ip_limit=1, scope="shared")._scope_for(_Request()) == "shared"
    )
