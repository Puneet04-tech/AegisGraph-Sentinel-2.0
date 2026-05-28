"""Tests for API key authentication on AegisGraph Sentinel 2.0 endpoints.

Two concerns are covered here:

1. The ``require_api_key`` dependency itself: missing key, wrong key,
   unconfigured server, and a valid key all produce the expected status
   codes. Each test patches ``AEGIS_API_KEY_HASHES`` for hermetic
   isolation so behaviour does not depend on the developer's shell.

2. The endpoint wiring: business endpoints refuse traffic without a
   valid key, and the public endpoints (``/``, ``/health``,
   ``/api/v1/health``, ``/stats``) remain reachable without one.

These tests use a bare ``TestClient(app)`` rather than the context-manager
form on purpose: the auth gate does not depend on lifespan-initialised
state, and running lifespan here would leave ``state.aegis_oracle`` (and
the other innovation managers) initialised for the rest of the session,
which breaks tests elsewhere that rely on those being None. The
conftest's ``api_client`` fixture is the one place that runs lifespan,
and it resets that state on teardown.

The auth tests are exempt from the conftest's ``_bypass_api_key_for_legacy_tests``
override (this file is listed in ``_AUTH_TEST_FILES``), so the real gate
fires here.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


# A static key/hash pair used by all "valid key" tests. The plaintext
# value is irrelevant — only the round-trip (hash on the server side,
# raw key in the header) needs to be consistent.
_VALID_KEY = "test-api-key-for-unit-tests-do-not-reuse"
_VALID_HASH = hashlib.sha256(_VALID_KEY.encode("utf-8")).hexdigest()


@pytest.fixture
def client_with_auth_configured(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """TestClient with ``AEGIS_API_KEY_HASHES`` set to a known hash.

    Bare TestClient (no ``with``) so lifespan does not run — see the
    module docstring for why that matters.
    """
    monkeypatch.setenv("AEGIS_API_KEY_HASHES", _VALID_HASH)
    from src.api.main import app

    yield TestClient(app)


@pytest.fixture
def client_without_auth_configured(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """TestClient with ``AEGIS_API_KEY_HASHES`` deliberately unset.

    Used to verify the fail-closed posture: gated endpoints must return
    503 rather than allowing traffic when the env var is missing.
    """
    monkeypatch.delenv("AEGIS_API_KEY_HASHES", raising=False)
    from src.api.main import app

    yield TestClient(app)


# ────────────────────────────────────────────────────────────
# Public endpoints — must stay reachable without a key
# ────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/health",
        "/api/v1/health",
        "/stats",
    ],
)
def test_public_endpoints_remain_open(
    client_with_auth_configured: TestClient, path: str
) -> None:
    """Public endpoints must respond 200 without an X-API-Key header."""
    response = client_with_auth_configured.get(path)
    assert response.status_code == 200, (
        f"Public endpoint {path} returned {response.status_code} "
        "without an API key. Health/stats endpoints must stay open."
    )


# ────────────────────────────────────────────────────────────
# Gated endpoints — must reject when key is missing or wrong
# ────────────────────────────────────────────────────────────

# Each entry: (method, path, sample body). The body is only used for
# POST endpoints and is intentionally minimal — the auth gate runs
# before body validation, so an empty dict is enough to exercise the
# gate without needing a fully-valid request model.
_GATED_ENDPOINTS = [
    ("POST", "/api/v1/fraud/check", {}),
    ("POST", "/api/v1/fraud/batch", {}),
    ("POST", "/api/v1/explain", {}),
    ("POST", "/api/v1/oracle/explain", {}),
    ("POST", "/api/v1/voice/analyze", {}),
    ("POST", "/api/v1/accounts/score-opening", {}),
    ("POST", "/api/v1/mule/assess", {}),
    ("POST", "/api/v1/blockchain/seal", {}),
    ("GET", "/api/v1/blockchain/verify/some-evidence-id", None),
    ("GET", "/api/v1/model/info", None),
]


@pytest.mark.parametrize(("method", "path", "body"), _GATED_ENDPOINTS)
def test_gated_endpoint_rejects_missing_key(
    client_with_auth_configured: TestClient,
    method: str,
    path: str,
    body: dict | None,
) -> None:
    """A request with no X-API-Key header must return 401."""
    if method == "GET":
        response = client_with_auth_configured.get(path)
    else:
        response = client_with_auth_configured.post(path, json=body)
    assert response.status_code == 401, (
        f"{method} {path} returned {response.status_code} without an "
        f"X-API-Key header; expected 401. Body: {response.text}"
    )


@pytest.mark.parametrize(("method", "path", "body"), _GATED_ENDPOINTS)
def test_gated_endpoint_rejects_wrong_key(
    client_with_auth_configured: TestClient,
    method: str,
    path: str,
    body: dict | None,
) -> None:
    """A request with an unrecognised X-API-Key must return 403."""
    headers = {"X-API-Key": "this-key-is-not-in-the-allowed-list"}
    if method == "GET":
        response = client_with_auth_configured.get(path, headers=headers)
    else:
        response = client_with_auth_configured.post(path, json=body, headers=headers)
    assert response.status_code == 403, (
        f"{method} {path} returned {response.status_code} with a wrong "
        f"X-API-Key; expected 403. Body: {response.text}"
    )


@pytest.mark.parametrize(("method", "path", "body"), _GATED_ENDPOINTS)
def test_gated_endpoint_accepts_valid_key(
    client_with_auth_configured: TestClient,
    method: str,
    path: str,
    body: dict | None,
) -> None:
    """A request with a valid X-API-Key must pass the auth gate.

    Downstream the request may still fail with 422 (body validation),
    500 (innovation module unavailable without lifespan), or 200 — all
    are evidence that the gate let the request through. The only
    statuses that would indicate the gate failed are 401, 403, and 503.
    """
    headers = {"X-API-Key": _VALID_KEY}
    if method == "GET":
        response = client_with_auth_configured.get(path, headers=headers)
    else:
        response = client_with_auth_configured.post(path, json=body, headers=headers)
    assert response.status_code not in (401, 403, 503), (
        f"{method} {path} returned {response.status_code} with a valid "
        f"X-API-Key; the auth gate should not have rejected this. "
        f"Body: {response.text}"
    )


# ────────────────────────────────────────────────────────────
# Misconfigured server — must fail closed
# ────────────────────────────────────────────────────────────

def test_gated_endpoint_returns_503_when_env_unset(
    client_without_auth_configured: TestClient,
) -> None:
    """Without AEGIS_API_KEY_HASHES set, gated endpoints must 503."""
    response = client_without_auth_configured.post(
        "/api/v1/fraud/check",
        json={},
        headers={"X-API-Key": "anything-at-all"},
    )
    assert response.status_code == 503, (
        f"With AEGIS_API_KEY_HASHES unset, /api/v1/fraud/check "
        f"returned {response.status_code}; expected 503 (fail closed). "
        f"Body: {response.text}"
    )


# ────────────────────────────────────────────────────────────
# Multi-hash list — supports zero-downtime rotation
# ────────────────────────────────────────────────────────────

def test_multiple_hashes_in_env_var_all_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both keys in a comma-separated AEGIS_API_KEY_HASHES are accepted."""
    key_a = "rotation-test-key-alpha"
    key_b = "rotation-test-key-beta"
    hash_a = hashlib.sha256(key_a.encode()).hexdigest()
    hash_b = hashlib.sha256(key_b.encode()).hexdigest()

    monkeypatch.setenv("AEGIS_API_KEY_HASHES", f"{hash_a},{hash_b}")
    from src.api.main import app

    client = TestClient(app)
    response_a = client.get("/api/v1/model/info", headers={"X-API-Key": key_a})
    response_b = client.get("/api/v1/model/info", headers={"X-API-Key": key_b})

    assert response_a.status_code not in (401, 403, 503), (
        f"Key A rejected during rotation window: {response_a.status_code}"
    )
    assert response_b.status_code not in (401, 403, 503), (
        f"Key B rejected during rotation window: {response_b.status_code}"
    )