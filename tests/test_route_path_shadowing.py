"""Static API paths must not be shadowed by a parameterised sibling.

FastAPI matches routes in declaration order. A path such as
/api/v1/campaigns/{campaign_id} declared before /api/v1/campaigns/stats
captures the literal path too, so the literal handler never runs and the caller
receives whatever the parameterised handler does with "stats" as the id.
"""

import hashlib
import re

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from src.api.main import app

ANALYST_KEY = "route-shadowing-test-key"
HEADERS = {"X-API-Key": ANALYST_KEY}


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


def _as_pattern(path):
    return re.compile("^" + re.sub(r"\{[^}]+\}", r"[^/]+", path) + "$")


def _shadowed_routes():
    """Return (earlier_parameterised, later_literal, methods) collisions."""
    routes = [r for r in app.routes if isinstance(r, APIRoute)]
    collisions = []
    for index, route in enumerate(routes):
        if "{" in route.path:
            continue
        for earlier in routes[:index]:
            if "{" not in earlier.path:
                continue
            shared = earlier.methods & route.methods - {"HEAD", "OPTIONS"}
            if shared and _as_pattern(earlier.path).match(route.path):
                collisions.append((earlier.path, route.path, sorted(shared)))
    return collisions


def test_no_literal_path_is_shadowed_by_an_earlier_parameterised_path():
    collisions = _shadowed_routes()

    assert not collisions, (
        "These literal paths are declared after a parameterised sibling that "
        f"matches them, so their handlers are unreachable: {collisions}. "
        "Move the literal declaration above the parameterised one."
    )


def test_campaign_stats_reaches_its_own_handler():
    response = TestClient(app).get("/api/v1/campaigns/stats", headers=HEADERS)

    assert response.status_code == 200
    assert "total_campaigns" in response.json(), (
        "the response did not come from get_campaign_stats"
    )


def test_campaign_discover_reaches_its_own_handler():
    response = TestClient(app).get(
        "/api/v1/campaigns/discover", params={"indicators": "a,b"}, headers=HEADERS
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_campaign_lookup_by_id_still_returns_not_found():
    response = TestClient(app).get(
        "/api/v1/campaigns/no-such-campaign", headers=HEADERS
    )

    assert response.status_code == 404
