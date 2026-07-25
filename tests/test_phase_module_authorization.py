"""Authorization contract for the phase module routers.

These routers are not mounted in src/api/main.py today, but several have been
mounted over time. Before this suite they authenticated by inspecting the shape
of the X-API-Key header, so any value beginning with "tenant_" was accepted and
the literal string "SUPER_ADMIN" granted system scope. Both are asserted to be
rejected here so mounting one cannot reintroduce that.
"""

import hashlib
import importlib
import pkgutil

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import src

ADMIN_KEY = "tenant_testco"
ADMIN_HASH = hashlib.sha256(ADMIN_KEY.encode()).hexdigest()


def _phase_api_modules():
    """Return every src.phase_* package that exposes an api router."""
    names = []
    for module in pkgutil.iter_modules(src.__path__):
        if not module.name.startswith("phase_"):
            continue
        try:
            api = importlib.import_module("src.%s.api" % module.name)
        except Exception:
            continue
        if hasattr(api, "router"):
            names.append((module.name, api.router))
    return names


PHASE_ROUTERS = _phase_api_modules()


@pytest.fixture(autouse=True)
def _admin_auth(monkeypatch):
    monkeypatch.setenv("AEGIS_ROLE_ADMIN", ADMIN_HASH)
    from src.api.security import _invalidate_auth_cache

    _invalidate_auth_cache()
    yield
    _invalidate_auth_cache()


def test_phase_routers_were_discovered():
    assert PHASE_ROUTERS, "no phase routers found, the discovery helper is broken"


def _client(router):
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.mark.parametrize(("name", "router"), PHASE_ROUTERS, ids=[n for n, _ in PHASE_ROUTERS])
def test_phase_router_rejects_attacker_chosen_tenant(name, router):
    """A caller must not select their own tenant by naming it in the header."""
    response = _client(router).get(
        "%s/records" % router.prefix, headers={"x-api-key": "tenant_attacker"}
    )
    assert response.status_code in (401, 403), (
        "%s served a request whose only credential was the tenant name" % name
    )


@pytest.mark.parametrize(("name", "router"), PHASE_ROUTERS, ids=[n for n, _ in PHASE_ROUTERS])
def test_phase_router_rejects_literal_super_admin(name, router):
    """The literal string SUPER_ADMIN is not a credential."""
    response = _client(router).get(
        "%s/records" % router.prefix, headers={"x-api-key": "SUPER_ADMIN"}
    )
    assert response.status_code in (401, 403), (
        "%s accepted the literal string SUPER_ADMIN as a credential" % name
    )


@pytest.mark.parametrize(("name", "router"), PHASE_ROUTERS, ids=[n for n, _ in PHASE_ROUTERS])
def test_phase_router_accepts_a_configured_admin_key(name, router):
    """A key whose hash is configured for ADMIN is still accepted."""
    response = _client(router).get(
        "%s/records" % router.prefix, headers={"x-api-key": ADMIN_KEY}
    )
    assert response.status_code == 200, (
        "%s rejected a correctly configured ADMIN key" % name
    )
