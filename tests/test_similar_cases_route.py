"""Route smoke tests for the case similarity search endpoint (issue #3087).

Verifies that ``find_similar_cases`` is actually registered on the FastAPI app
so an authorised analyst can reach it instead of getting a 404.
"""

import hashlib
import sys
import types
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


_ANALYST_KEY = "test-analyst-key-similar-cases-3087"
_ANALYST_HASH = hashlib.sha256(_ANALYST_KEY.encode("utf-8")).hexdigest()


def _import_app():
    """Import the API app, tolerating the unrelated broken warfare_routes import.

    ``src.api.warfare_routes`` currently raises ``NameError`` at import time
    (``Dict[str, Any]`` used without importing ``Any``) on master, which blocks
    ``from src.api.main import app``.  Until that is fixed upstream, substitute
    a minimal router so the app can be constructed; once the real module
    imports cleanly the stub is not installed.
    """
    try:
        import src.api.warfare_routes  # noqa: F401
    except NameError:
        from fastapi import APIRouter

        stub = types.ModuleType("src.api.warfare_routes")
        stub.router = APIRouter()
        sys.modules["src.api.warfare_routes"] = stub

    from src.api.main import app

    return app


@pytest.fixture
def client_with_analyst_role(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """TestClient configured with a valid ANALYST-role API key."""
    monkeypatch.setenv("AEGIS_ROLE_ANALYST", _ANALYST_HASH)
    app = _import_app()
    with TestClient(app) as client:
        yield client


def _analyst_headers() -> dict:
    return {"X-API-Key": _ANALYST_KEY}


def test_similar_cases_endpoint_registered(client_with_analyst_role) -> None:
    """An authorised analyst gets a response (not 404) from the similar-cases route."""
    response = client_with_analyst_role.post(
        "/api/v1/cases/similar",
        headers=_analyst_headers(),
        json={"query_text": "Suspicious transfer to new recipient detected", "k": 5},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "similar_cases" in body
    assert "total_found" in body
    assert "query_text_used" in body
    assert "processing_time_ms" in body
    assert "timestamp" in body


def test_similar_cases_endpoint_requires_analyst_role(client_with_analyst_role) -> None:
    """The route is role-gated: an unauthenticated request is rejected."""
    response = client_with_analyst_role.post(
        "/api/v1/cases/similar",
        json={"query_text": "Suspicious transfer", "k": 5},
    )
    assert response.status_code in (401, 403), response.text
