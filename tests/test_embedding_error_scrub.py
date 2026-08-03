"""Tests for scrubbing internal exception details from the embedding route.

Issue #2737: the generate-embedding endpoint must return a generic 500
message and log full details server-side only.
"""

import hashlib
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


_ANALYST_KEY = "test-analyst-key-for-error-scrub"
_ANALYST_HASH = hashlib.sha256(_ANALYST_KEY.encode("utf-8")).hexdigest()

_INTERNAL_DETAIL = "/opt/app/models/embedder/model.pkl: expected 512 features"


class _RaisingEmbedder:
    def embed_text(self, text: str):
        raise RuntimeError(_INTERNAL_DETAIL)


@pytest.fixture
def client_with_analyst_role(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """TestClient configured with a valid ANALYST-role API key."""
    monkeypatch.setenv("AEGIS_ROLE_ANALYST", _ANALYST_HASH)
    from src.api.main import app

    yield TestClient(app)


def test_embedding_error_is_scrubbed(client_with_analyst_role, monkeypatch) -> None:
    monkeypatch.setattr(
        "src.embeddings.get_embedder", lambda *a, **k: _RaisingEmbedder()
    )

    response = client_with_analyst_role.post(
        "/api/v1/cases/generate-embedding",
        headers={"X-API-Key": _ANALYST_KEY},
        json={"text": "Suspicious transfer detected"},
    )

    assert response.status_code == 500
    error_payload = response.json()["error"]
    assert error_payload["message"] == "Internal error generating embedding"
    assert _INTERNAL_DETAIL not in response.text
