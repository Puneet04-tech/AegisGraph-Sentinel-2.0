"""Route-level tests for the case similarity and embedding endpoints.

Verifies that the two endpoints no longer share a single handler and each
returns its own response model shape (issue #2736).
"""

import hashlib
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


_ANALYST_KEY = "test-analyst-key-for-similarity-routes"
_ANALYST_HASH = hashlib.sha256(_ANALYST_KEY.encode("utf-8")).hexdigest()


@pytest.fixture
def client_with_analyst_role(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """TestClient configured with a valid ANALYST-role API key."""
    monkeypatch.setenv("AEGIS_ROLE_ANALYST", _ANALYST_HASH)
    from src.api.main import app

    yield TestClient(app)


def _analyst_headers() -> dict:
    return {"X-API-Key": _ANALYST_KEY}


def test_generate_embedding_returns_embedding_shape(client_with_analyst_role) -> None:
    response = client_with_analyst_role.post(
        "/api/v1/cases/generate-embedding",
        headers=_analyst_headers(),
        json={"text": "Suspicious transfer to new recipient detected"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "embedding_dimension" in body
    assert "embedding_preview" in body
    assert "timestamp" in body
    assert "similar_cases" not in body


def test_similar_cases_returns_similar_case_shape(client_with_analyst_role) -> None:
    response = client_with_analyst_role.post(
        "/api/v1/cases/similar-cases",
        headers=_analyst_headers(),
        json={"query_text": "Suspicious transfer to new recipient detected", "k": 5},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "similar_cases" in body
    assert "total_found" in body
    assert "query_text_used" in body
    assert "processing_time_ms" in body
    assert "embedding_preview" not in body
