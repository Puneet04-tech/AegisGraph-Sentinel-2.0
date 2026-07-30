"""Bad input to the entity link endpoint must be a client error, not a 500.

EntityResolver.link_entities raises ValueError for input it cannot act on, and
the entity model raises when asked to build an entity with no value. Neither was
caught, so a malformed request reached the caller as an internal server error.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from src.api.main import app

ANALYST_KEY = "entity-link-validation-key"
HEADERS = {"X-API-Key": ANALYST_KEY}
ENDPOINT = "/api/v1/entity-resolution/link"


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


def _clear_rate_limit_state():
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


def _post(body):
    return TestClient(app).post(ENDPOINT, headers=HEADERS, json=body)


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("empty body", {}),
        ("source only", {"source_value": "ACC1"}),
        ("target only", {"target_value": "ACC2"}),
        ("blank strings", {"source_value": "", "target_value": ""}),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_missing_identifier_is_a_client_error(label, body):
    response = _post(body)

    assert response.status_code == 422, (
        f"{label} produced {response.status_code}; a request missing a required "
        "identifier is a client error, not a server fault"
    )


def test_unresolvable_entity_ids_are_a_client_error():
    """An id that resolves to nothing must not surface as a 500."""
    response = _post(
        {"source_entity_id": "no-such-entity-1", "target_entity_id": "no-such-entity-2"}
    )

    assert response.status_code < 500, (
        f"unresolvable entity ids produced {response.status_code}"
    )


def test_a_valid_link_still_succeeds():
    response = _post({"source_value": "ACC-LINK-1", "target_value": "ACC-LINK-2"})

    assert response.status_code == 200, response.text
    assert response.json()["success"] is True


def test_schema_declares_the_constraint():
    """The either/or rule belongs in the schema so it reaches the OpenAPI spec."""
    from src.api.schemas import EntityLinkRequest

    with pytest.raises(Exception) as excinfo:
        EntityLinkRequest()

    assert "source_entity_id" in str(excinfo.value) or "source_value" in str(
        excinfo.value
    )
