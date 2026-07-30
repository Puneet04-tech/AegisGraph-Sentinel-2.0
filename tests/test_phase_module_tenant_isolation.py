"""A phase module must not accept a tenant chosen by the caller.

The mounted phase routers derived the tenant by splitting the API key text, and
returned "system" for any key that did not start with "tenant_". The create
handler skipped its own ownership check for "system", so every ordinary key
could write a record into any tenant it named.
"""

import hashlib
import re

import io
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.security import _invalidate_auth_cache
from src.api.tenant_dependency import tenant_for_key
from src.api.validators import reset_rate_limiter

API_KEY = "phase-tenant-contract-key"

RECORD_BODIES = {
    "/api/v1/phase61/records": {
        "record_id": "R-ISO-61", "relation_id": "REL-1", "source_entity": "E1",
        "target_entity": "E2", "relation_type": "LINK", "confidence": 0.9,
    },
}


def _mounted_phase_modules():
    modules = set()
    for route in app.routes:
        if isinstance(route, APIRoute) and route.endpoint.__module__.startswith("src.phase"):
            modules.add(route.endpoint.__module__)
    return sorted(modules)


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    digest = hashlib.sha256(API_KEY.encode()).hexdigest()
    for role in ("ADMIN", "SUPER_ADMIN"):
        monkeypatch.setenv(f"AEGIS_ROLE_{role}", digest)
    _invalidate_auth_cache()
    reset_rate_limiter()
    yield
    reset_rate_limiter()
    _invalidate_auth_cache()


def test_a_caller_cannot_write_into_a_tenant_it_does_not_own():
    client = TestClient(app)
    path, body = next(iter(RECORD_BODIES.items()))
    payload = dict(body, tenant_id="a-tenant-i-do-not-own")

    response = client.post(path, headers={"X-API-Key": API_KEY}, json=payload)

    assert response.status_code == 403, (
        f"{path} accepted a record for a tenant the caller does not own and "
        f"answered {response.status_code}. The tenant check is skipped whenever "
        "the caller resolves to a shared fallback."
    )


def test_a_caller_can_still_write_into_its_own_tenant():
    """Closing the hole must not make the endpoint unusable."""
    client = TestClient(app)
    path, body = next(iter(RECORD_BODIES.items()))
    payload = dict(body, tenant_id=tenant_for_key(API_KEY))

    response = client.post(path, headers={"X-API-Key": API_KEY}, json=payload)

    assert response.status_code == 200, response.text[:150]
    assert response.json()["status"] == "RECORD_CREATED"


def test_reads_are_scoped_to_the_callers_own_tenant():
    client = TestClient(app)
    path, body = next(iter(RECORD_BODIES.items()))
    client.post(
        path,
        headers={"X-API-Key": API_KEY},
        json=dict(body, tenant_id=tenant_for_key(API_KEY), record_id="R-ISO-SCOPE"),
    )

    listed = client.get(path, headers={"X-API-Key": API_KEY}).json()

    assert listed["tenant_id"] == tenant_for_key(API_KEY)


def test_two_keys_resolve_to_two_tenants():
    assert tenant_for_key("key-one") != tenant_for_key("key-two")
    assert tenant_for_key("key-one") == tenant_for_key("key-one")


def test_the_tenant_is_not_readable_out_of_the_key_text():
    """The identity must not be carried by the secret itself."""
    assert "tenant_secret" not in tenant_for_key("tenant_secret")


@pytest.mark.parametrize("module", _mounted_phase_modules(), ids=lambda m: m.split(".")[1])
def test_no_mounted_phase_module_derives_a_tenant_from_the_key(module):
    source_path = module.replace(".", "/") + ".py"
    source = io.open(source_path, encoding="utf-8").read()

    assert not re.search(r'x_api_key\.startswith\("tenant_"\)', source), (
        f"{source_path} still splits the API key to decide the tenant, so the "
        "secret carries the identity"
    )
    assert 'return "system"' not in source, (
        f"{source_path} still falls back to a shared tenant, which its own "
        "ownership check treats as permission to write anywhere"
    )
