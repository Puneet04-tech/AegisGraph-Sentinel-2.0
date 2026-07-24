"""Authorization contract for role-protected API routes.

Every route listed in PROTECTED_ROUTES declares a require_role dependency and
must reject an unauthenticated caller. The list is checked in deliberately so
that deleting a require_role dependency fails this suite instead of passing
silently.

This module is not listed in the conftest ``_LEGACY_BYPASS_FILES`` set, so the
real security dependencies run here rather than the legacy bypass.
"""

import hashlib

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.security import _invalidate_auth_cache

# Route inventory, sorted by method then path. Regenerate with the helper in
# test_protected_route_inventory_is_current when a route is added or removed.
PROTECTED_ROUTES = [
    ("GET", "/api/v1/actors"),
    ("GET", "/api/v1/actors/{actor_id}"),
    ("GET", "/api/v1/actors/{actor_id}/profile"),
    ("GET", "/api/v1/adaptive-auth/audit"),
    ("GET", "/api/v1/adaptive-auth/audit/summary"),
    ("GET", "/api/v1/adaptive-auth/challenge-types"),
    ("GET", "/api/v1/adaptive-auth/policies"),
    ("GET", "/api/v1/adaptive-auth/session/{session_id}"),
    ("GET", "/api/v1/adaptive-auth/stats"),
    ("GET", "/api/v1/adversary/profiles/{profile_id}"),
    ("GET", "/api/v1/adversary/results"),
    ("GET", "/api/v1/analytics/insights"),
    ("GET", "/api/v1/analytics/kpi/dashboard"),
    ("GET", "/api/v1/analytics/kpis"),
    ("GET", "/api/v1/analytics/stats"),
    ("GET", "/api/v1/archival/archive"),
    ("GET", "/api/v1/archival/hot"),
    ("GET", "/api/v1/archival/runs"),
    ("GET", "/api/v1/archival/stats"),
    ("GET", "/api/v1/blockchain/verify/{evidence_id}"),
    ("GET", "/api/v1/bulk/status/{task_id}"),
    ("GET", "/api/v1/campaigns"),
    ("GET", "/api/v1/campaigns/discover"),
    ("GET", "/api/v1/campaigns/stats"),
    ("GET", "/api/v1/campaigns/{campaign_id}"),
    ("GET", "/api/v1/campaigns/{campaign_id}/profile"),
    ("GET", "/api/v1/campaigns/{campaign_id}/risk"),
    ("GET", "/api/v1/cases"),
    ("GET", "/api/v1/cases/dashboard"),
    ("GET", "/api/v1/cases/investigation-insights/{case_id}"),
    ("GET", "/api/v1/cases/{case_id}"),
    ("GET", "/api/v1/cases/{case_id}/timeline"),
    ("GET", "/api/v1/decision/audit"),
    ("GET", "/api/v1/decision/explain/{decision_id}"),
    ("GET", "/api/v1/decision/governance/stats"),
    ("GET", "/api/v1/decision/history"),
    ("GET", "/api/v1/decision/recommend"),
    ("GET", "/api/v1/entity-resolution/cluster/{cluster_id}"),
    ("GET", "/api/v1/entity-resolution/contagion/{entity_id}"),
    ("GET", "/api/v1/entity-resolution/entity/{entity_id}"),
    ("GET", "/api/v1/entity-resolution/high-risk-rings"),
    ("GET", "/api/v1/entity-resolution/network/{entity_id}"),
    ("GET", "/api/v1/entity-resolution/stats"),
    ("GET", "/api/v1/governance/audit/findings"),
    ("GET", "/api/v1/governance/compliance/frameworks"),
    ("GET", "/api/v1/governance/stats"),
    ("GET", "/api/v1/honeypot/active"),
    ("GET", "/api/v1/honeypot/stats"),
    ("GET", "/api/v1/identity/audit"),
    ("GET", "/api/v1/identity/providers"),
    ("GET", "/api/v1/identity/providers/{provider_id}"),
    ("GET", "/api/v1/identity/stats"),
    ("GET", "/api/v1/identity/user/{user_id}"),
    ("GET", "/api/v1/model/info"),
    ("GET", "/api/v1/monitoring/memory"),
    ("GET", "/api/v1/phase61/analytics"),
    ("GET", "/api/v1/phase61/records"),
    ("GET", "/api/v1/phase61/records/{record_id}"),
    ("GET", "/api/v1/phase62/analytics"),
    ("GET", "/api/v1/phase62/records"),
    ("GET", "/api/v1/phase62/records/{record_id}"),
    ("GET", "/api/v1/phase63/analytics"),
    ("GET", "/api/v1/phase63/records"),
    ("GET", "/api/v1/phase63/records/{record_id}"),
    ("GET", "/api/v1/phase64/analytics"),
    ("GET", "/api/v1/phase64/records"),
    ("GET", "/api/v1/phase64/records/{record_id}"),
    ("GET", "/api/v1/phase66/analytics"),
    ("GET", "/api/v1/phase66/records"),
    ("GET", "/api/v1/phase66/records/{record_id}"),
    ("GET", "/api/v1/phase67/analytics"),
    ("GET", "/api/v1/phase67/records"),
    ("GET", "/api/v1/phase67/records/{record_id}"),
    ("GET", "/api/v1/predictive/attack-paths"),
    ("GET", "/api/v1/predictive/campaigns"),
    ("GET", "/api/v1/predictive/forecast"),
    ("GET", "/api/v1/predictive/recommendations"),
    ("GET", "/api/v1/predictive/stats"),
    ("GET", "/api/v1/soar/audit"),
    ("GET", "/api/v1/soar/dashboard"),
    ("GET", "/api/v1/soar/incidents"),
    ("GET", "/api/v1/soar/incidents/{incident_id}"),
    ("GET", "/api/v1/soar/workflows"),
    ("GET", "/api/v1/soc/dashboard"),
    ("GET", "/api/v1/soc/fraud-rings"),
    ("GET", "/api/v1/soc/stats"),
    ("GET", "/api/v1/threat-hunting/anomalies"),
    ("GET", "/api/v1/threat-hunting/attack-paths"),
    ("GET", "/api/v1/threat-hunting/campaigns"),
    ("GET", "/api/v1/threat-hunting/dashboard"),
    ("GET", "/api/v1/threat-hunting/hunt/{hunt_id}"),
    ("GET", "/api/v1/threat-hunting/hunts"),
    ("GET", "/api/v1/threat-hunting/results/{hunt_id}"),
    ("GET", "/api/v1/zero-trust/device/{device_id}"),
    ("GET", "/api/v1/zero-trust/policies"),
    ("GET", "/api/v1/zero-trust/session/{session_id}"),
    ("GET", "/api/v1/zero-trust/stats"),
    ("GET", "/api/v1/zero-trust/user/{user_id}/anomalies"),
    ("GET", "/api/v1/zero-trust/user/{user_id}/devices"),
    ("GET", "/stats"),
    ("PATCH", "/api/v1/cases/{case_id}"),
    ("POST", "/api/v1/accounts/score-opening"),
    ("POST", "/api/v1/actors"),
    ("POST", "/api/v1/adaptive-auth/challenge"),
    ("POST", "/api/v1/adaptive-auth/evaluate"),
    ("POST", "/api/v1/adaptive-auth/policies"),
    ("POST", "/api/v1/adaptive-auth/session/reassess"),
    ("POST", "/api/v1/adaptive-auth/verify"),
    ("POST", "/api/v1/adversary/campaigns/generate"),
    ("POST", "/api/v1/adversary/profiles"),
    ("POST", "/api/v1/adversary/simulate/start"),
    ("POST", "/api/v1/alerts/summarize"),
    ("POST", "/api/v1/analytics/correlation/analyze"),
    ("POST", "/api/v1/analytics/dashboard/create"),
    ("POST", "/api/v1/analytics/metric/define"),
    ("POST", "/api/v1/analytics/metric/record"),
    ("POST", "/api/v1/analytics/report/generate"),
    ("POST", "/api/v1/analytics/report/schedule"),
    ("POST", "/api/v1/analytics/trend/analyze"),
    ("POST", "/api/v1/archival/logs"),
    ("POST", "/api/v1/archival/trigger"),
    ("POST", "/api/v1/blockchain/export"),
    ("POST", "/api/v1/blockchain/seal"),
    ("POST", "/api/v1/bulk/ingest"),
    ("POST", "/api/v1/bulk/ingest/file"),
    ("POST", "/api/v1/campaigns"),
    ("POST", "/api/v1/campaigns/correlate"),
    ("POST", "/api/v1/campaigns/{campaign_id}/attribute"),
    ("POST", "/api/v1/cases"),
    ("POST", "/api/v1/cases/generate-embedding"),
    ("POST", "/api/v1/cases/similar-cases"),
    ("POST", "/api/v1/cases/{case_id}/claim"),
    ("POST", "/api/v1/cases/{case_id}/comments"),
    ("POST", "/api/v1/cases/{case_id}/evidence"),
    ("POST", "/api/v1/decision/audit"),
    ("POST", "/api/v1/decision/evaluate"),
    ("POST", "/api/v1/entity-resolution/detect-rings"),
    ("POST", "/api/v1/entity-resolution/link"),
    ("POST", "/api/v1/entity-resolution/propagate"),
    ("POST", "/api/v1/explain"),
    ("POST", "/api/v1/fraud/batch"),
    ("POST", "/api/v1/fraud/check"),
    ("POST", "/api/v1/governance/audit/finding"),
    ("POST", "/api/v1/governance/board-report"),
    ("POST", "/api/v1/governance/compliance/gap-analysis"),
    ("POST", "/api/v1/governance/dashboard"),
    ("POST", "/api/v1/governance/report"),
    ("POST", "/api/v1/governance/risk-scorecard"),
    ("POST", "/api/v1/graph/blast-radius"),
    ("POST", "/api/v1/identity/providers/register"),
    ("POST", "/api/v1/identity/provision"),
    ("POST", "/api/v1/mule/assess"),
    ("POST", "/api/v1/oracle/explain"),
    ("POST", "/api/v1/phase61/records"),
    ("POST", "/api/v1/phase62/records"),
    ("POST", "/api/v1/phase63/records"),
    ("POST", "/api/v1/phase64/records"),
    ("POST", "/api/v1/phase66/records"),
    ("POST", "/api/v1/phase67/records"),
    ("POST", "/api/v1/predictive/recommendations/generate"),
    ("POST", "/api/v1/predictive/simulate"),
    ("POST", "/api/v1/soar/contain"),
    ("POST", "/api/v1/soar/incidents"),
    ("POST", "/api/v1/soar/playbooks"),
    ("POST", "/api/v1/soar/playbooks/execute"),
    ("POST", "/api/v1/soar/respond"),
    ("POST", "/api/v1/soc/forensics/analyze"),
    ("POST", "/api/v1/soc/fraud-ring/detect"),
    ("POST", "/api/v1/soc/investigate"),
    ("POST", "/api/v1/soc/orchestrate"),
    ("POST", "/api/v1/soc/report/generate"),
    ("POST", "/api/v1/soc/threat/analyze"),
    ("POST", "/api/v1/threat-hunting/correlate"),
    ("POST", "/api/v1/threat-hunting/query"),
    ("POST", "/api/v1/threat-hunting/start"),
    ("POST", "/api/v1/voice/analyze"),
    ("POST", "/api/v1/zero-trust/device/register"),
    ("POST", "/api/v1/zero-trust/device/{device_id}/block"),
    ("POST", "/api/v1/zero-trust/device/{device_id}/unblock"),
    ("POST", "/api/v1/zero-trust/evaluate"),
    ("POST", "/api/v1/zero-trust/session/analyze"),
]

# Routes that are intentionally reachable without credentials.
PUBLIC_ROUTES = {
    ("GET", "/"),
    ("GET", "/health"),
    ("GET", "/health/liveness"),
    ("GET", "/health/readiness"),
    ("GET", "/api/v1/health"),
    ("GET", "/metrics"),
    ("GET", "/docs"),
    ("GET", "/redoc"),
    ("GET", "/openapi.json"),
}

_UNAUTHENTICATED_STATUSES = {401, 403, 503}


@pytest.fixture(autouse=True)
def _configure_api_keys(monkeypatch):
    """Configure a key backend so the gate returns 401 rather than 503."""
    monkeypatch.setenv("AEGIS_ROLE_ANALYST", hashlib.sha256(b"contract-test-key").hexdigest())
    _invalidate_auth_cache()
    yield
    _invalidate_auth_cache()


def _current_protected_routes():
    """Return the (method, path) pairs currently gated by require_role."""
    found = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for depends_obj in route.dependencies:
            fn = getattr(depends_obj, "dependency", None)
            qualname = getattr(fn, "__qualname__", "")
            if qualname.startswith("require_role"):
                for method in route.methods - {"HEAD", "OPTIONS"}:
                    found.add((method, route.path))
    return found


def _clear_rate_limit_state():
    """Drop accumulated rate limit counters so 429 cannot mask the auth result."""
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


# The live checks below issue real requests, which the global rate limit
# middleware counts. Sampling keeps the suite well inside that budget while
# test_protected_route_inventory_is_current still covers every route.
_LIVE_SAMPLE_SIZE = 12
_LIVE_SAMPLE = PROTECTED_ROUTES[:: max(1, len(PROTECTED_ROUTES) // _LIVE_SAMPLE_SIZE)]


@pytest.mark.parametrize(("method", "path"), _LIVE_SAMPLE)
def test_protected_route_rejects_anonymous_request(method, path):
    """A sampled route must not serve an unauthenticated caller."""
    _clear_rate_limit_state()
    client = TestClient(app)
    request_path = path.replace("{", "").replace("}", "")
    response = client.request(method, request_path, json={})

    assert response.status_code in _UNAUTHENTICATED_STATUSES, (
        f"{method} {path} answered {response.status_code} without credentials. "
        "If this route was made public on purpose, move it to PUBLIC_ROUTES and "
        "record why in the pull request."
    )


def test_protected_route_inventory_is_current():
    """The checked-in inventory must match the routes gated at runtime."""
    current = _current_protected_routes()
    expected = set(PROTECTED_ROUTES)

    removed = sorted(expected - current)
    added = sorted(current - expected)

    assert not removed, (
        "These routes no longer declare require_role: "
        f"{removed}. Restore the dependency, or delete the entry from "
        "PROTECTED_ROUTES if the route was removed or made public on purpose."
    )
    assert not added, (
        "These routes are gated but missing from the inventory: "
        f"{added}. Add them to PROTECTED_ROUTES so a future removal is caught."
    )


def test_public_routes_remain_reachable():
    """The documented public surface must not require credentials."""
    client = TestClient(app)
    for method, path in sorted(PUBLIC_ROUTES):
        response = client.request(method, path)
        if response.status_code == 404:
            continue
        assert response.status_code not in _UNAUTHENTICATED_STATUSES, (
            f"{method} {path} is documented as public but answered "
            f"{response.status_code} without credentials."
        )
