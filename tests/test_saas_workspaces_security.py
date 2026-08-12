"""Authentication, authorisation and tenant isolation for the workspace router.

Every endpoint in this router previously ran with no authentication dependency,
no organisation check and no tenant scoping, while its two sibling routers
(organizations, billing) both enforced `get_current_user` plus
`_require_org_access` on every call. These tests pin the gap closed.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.saas.routes import workspaces as workspace_routes
from src.saas.routes.auth import get_current_user

# The workspace router is deliberately NOT mounted on the production app, in
# line with the other SaaS routers, so its access control is exercised on a
# router-local app -- mirroring tests/test_saas_users_security.py.
app = FastAPI()
app.include_router(workspace_routes.router)

ORG_A = "org_alpha"
ORG_B = "org_beta"

ADMIN_A = {"user_id": "u_admin_a", "organization_id": ORG_A, "role": "admin"}
MEMBER_A = {"user_id": "u_member_a", "organization_id": ORG_A, "role": "member"}
ADMIN_B = {"user_id": "u_admin_b", "organization_id": ORG_B, "role": "admin"}
NO_TENANT = {"user_id": "u_stray", "organization_id": None, "role": "admin"}


@pytest.fixture
def api_client():
    with TestClient(app) as client:
        yield client


def _as(user):
    app.dependency_overrides[get_current_user] = lambda: user


@pytest.fixture(autouse=True)
def _reset_state():
    workspace_routes.reset_workspace_store()
    yield
    workspace_routes.reset_workspace_store()
    app.dependency_overrides.pop(get_current_user, None)


def _create(api_client, user=ADMIN_A, name="Fraud Ops", slug="fraud-ops"):
    _as(user)
    response = api_client.post("/api/v1/workspaces/", json={"name": name, "slug": slug})
    assert response.status_code == 201, response.text
    return response.json()


class TestAuthenticationRequired:
    """Every endpoint must reject an unauthenticated caller.

    With no dependency override installed, `get_current_user` runs for real and
    rejects the request; previously these endpoints had no dependency at all.
    """

    ENDPOINTS = [
        ("post", "/api/v1/workspaces/"),
        ("get", "/api/v1/workspaces/"),
        ("get", "/api/v1/workspaces/ws_abc"),
        ("patch", "/api/v1/workspaces/ws_abc"),
        ("delete", "/api/v1/workspaces/ws_abc"),
        ("get", "/api/v1/workspaces/ws_abc/members"),
        ("post", "/api/v1/workspaces/ws_abc/members?user_id=u_1"),
        ("patch", "/api/v1/workspaces/ws_abc/members/u_1"),
        ("delete", "/api/v1/workspaces/ws_abc/members/u_1"),
        ("get", "/api/v1/workspaces/ws_abc/cases"),
        ("get", "/api/v1/workspaces/ws_abc/settings"),
        ("patch", "/api/v1/workspaces/ws_abc/settings"),
    ]

    @pytest.mark.parametrize("method,path", ENDPOINTS)
    def test_endpoint_rejects_anonymous_callers(self, api_client, method, path):
        # request() is used rather than the per-verb helpers because this client
        # rejects a json body on GET and DELETE.
        kwargs = {"json": {}} if method in ("post", "patch", "put") else {}
        response = api_client.request(method.upper(), path, **kwargs)
        assert response.status_code in (401, 403), (
            f"{method.upper()} {path} answered anonymously with {response.status_code}"
        )


class TestTenantIsolation:
    def test_workspace_from_another_tenant_reports_not_found(self, api_client):
        created = _create(api_client)

        _as(ADMIN_B)
        response = api_client.get(f"/api/v1/workspaces/{created['id']}")
        # 404 rather than 403, so existence is not disclosed across tenants.
        assert response.status_code == 404

    def test_cross_tenant_update_is_refused(self, api_client):
        created = _create(api_client)

        _as(ADMIN_B)
        response = api_client.patch(
            f"/api/v1/workspaces/{created['id']}", json={"name": "Hijacked"}
        )
        assert response.status_code == 404

    def test_cross_tenant_delete_is_refused(self, api_client):
        _create(api_client)
        second = _create(api_client, name="Second", slug="second")

        _as(ADMIN_B)
        assert api_client.delete(f"/api/v1/workspaces/{second['id']}").status_code == 404

    def test_cross_tenant_member_addition_is_refused(self, api_client):
        created = _create(api_client)

        _as(ADMIN_B)
        response = api_client.post(
            f"/api/v1/workspaces/{created['id']}/members?user_id=u_intruder"
        )
        assert response.status_code == 404

    def test_cross_tenant_settings_read_is_refused(self, api_client):
        created = _create(api_client)

        _as(ADMIN_B)
        assert api_client.get(f"/api/v1/workspaces/{created['id']}/settings").status_code == 404

    def test_listing_only_returns_the_callers_tenant(self, api_client):
        _create(api_client, ADMIN_A, "Alpha WS", "alpha-ws")
        _create(api_client, ADMIN_B, "Beta WS", "beta-ws")

        _as(ADMIN_A)
        listed = api_client.get("/api/v1/workspaces/").json()
        assert [w["name"] for w in listed] == ["Alpha WS"]
        assert all(w["organization_id"] == ORG_A for w in listed)

    def test_supplied_organization_id_cannot_redirect_the_write(self, api_client):
        _as(ADMIN_A)
        response = api_client.post(
            f"/api/v1/workspaces/?organization_id={ORG_B}",
            json={"name": "Smuggled", "slug": "smuggled"},
        )
        assert response.status_code == 403

    def test_matching_organization_id_is_accepted(self, api_client):
        _as(ADMIN_A)
        response = api_client.post(
            f"/api/v1/workspaces/?organization_id={ORG_A}",
            json={"name": "Fine", "slug": "fine"},
        )
        assert response.status_code == 201
        assert response.json()["organization_id"] == ORG_A

    def test_caller_without_a_tenant_is_rejected(self, api_client):
        _as(NO_TENANT)
        response = api_client.post(
            "/api/v1/workspaces/", json={"name": "Orphan", "slug": "orphan"}
        )
        assert response.status_code == 401


class TestAdminGating:
    def test_non_admin_cannot_create(self, api_client):
        _as(MEMBER_A)
        response = api_client.post(
            "/api/v1/workspaces/", json={"name": "Nope", "slug": "nope"}
        )
        assert response.status_code == 403

    def test_non_admin_cannot_update(self, api_client):
        created = _create(api_client)
        _as(MEMBER_A)
        assert api_client.patch(
            f"/api/v1/workspaces/{created['id']}", json={"name": "x"}
        ).status_code == 403

    def test_non_admin_cannot_delete(self, api_client):
        _create(api_client)
        second = _create(api_client, name="Second", slug="second")
        _as(MEMBER_A)
        assert api_client.delete(f"/api/v1/workspaces/{second['id']}").status_code == 403

    def test_non_admin_cannot_add_members(self, api_client):
        created = _create(api_client)
        _as(MEMBER_A)
        assert api_client.post(
            f"/api/v1/workspaces/{created['id']}/members?user_id=u_1"
        ).status_code == 403

    def test_non_admin_cannot_change_settings(self, api_client):
        created = _create(api_client)
        _as(MEMBER_A)
        assert api_client.patch(
            f"/api/v1/workspaces/{created['id']}/settings",
            json={"auto_assignment": False},
        ).status_code == 403

    def test_non_admin_can_still_read(self, api_client):
        created = _create(api_client)
        _as(MEMBER_A)
        assert api_client.get(f"/api/v1/workspaces/{created['id']}").status_code == 200
        assert api_client.get(f"/api/v1/workspaces/{created['id']}/settings").status_code == 200
        assert api_client.get(f"/api/v1/workspaces/{created['id']}/cases").status_code == 200


class TestPersistence:
    def test_reads_reflect_writes(self, api_client):
        created = _create(api_client, name="Original", slug="original")

        _as(ADMIN_A)
        api_client.patch(f"/api/v1/workspaces/{created['id']}", json={"name": "Renamed"})
        fetched = api_client.get(f"/api/v1/workspaces/{created['id']}").json()
        assert fetched["name"] == "Renamed"

    def test_get_no_longer_returns_a_hardcoded_org(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        fetched = api_client.get(f"/api/v1/workspaces/{created['id']}").json()
        assert fetched["organization_id"] == ORG_A
        assert fetched["organization_id"] != "org_123"

    def test_unknown_workspace_is_not_found(self, api_client):
        _as(ADMIN_A)
        assert api_client.get("/api/v1/workspaces/ws_missing").status_code == 404

    def test_slug_is_unique_within_an_organization(self, api_client):
        _create(api_client, slug="shared")
        _as(ADMIN_A)
        response = api_client.post(
            "/api/v1/workspaces/", json={"name": "Dup", "slug": "shared"}
        )
        assert response.status_code == 409

    def test_same_slug_is_allowed_in_a_different_organization(self, api_client):
        _create(api_client, ADMIN_A, "Alpha", "shared")
        response_b = _create(api_client, ADMIN_B, "Beta", "shared")
        assert response_b["organization_id"] == ORG_B

    def test_first_workspace_becomes_the_default(self, api_client):
        first = _create(api_client, slug="first")
        second = _create(api_client, name="Second", slug="second")
        assert first["is_default"] is True
        assert second["is_default"] is False

    def test_default_workspace_cannot_be_deleted(self, api_client):
        first = _create(api_client, slug="first")
        _as(ADMIN_A)
        assert api_client.delete(f"/api/v1/workspaces/{first['id']}").status_code == 409

    def test_delete_removes_the_workspace(self, api_client):
        _create(api_client, slug="first")
        second = _create(api_client, name="Second", slug="second")

        _as(ADMIN_A)
        assert api_client.delete(f"/api/v1/workspaces/{second['id']}").status_code == 204
        assert api_client.get(f"/api/v1/workspaces/{second['id']}").status_code == 404


class TestMembers:
    def test_member_lifecycle(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        path = f"/api/v1/workspaces/{created['id']}/members"

        assert api_client.post(f"{path}?user_id=u_1&role=member").status_code == 200
        assert [m["user_id"] for m in api_client.get(path).json()] == ["u_1"]

        updated = api_client.patch(f"{path}/u_1?role=admin")
        assert updated.status_code == 200
        assert updated.json()["role"] == "admin"

        assert api_client.delete(f"{path}/u_1").status_code == 200
        assert api_client.get(path).json() == []

    def test_duplicate_member_is_rejected(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        path = f"/api/v1/workspaces/{created['id']}/members"

        api_client.post(f"{path}?user_id=u_1")
        assert api_client.post(f"{path}?user_id=u_1").status_code == 409

    def test_member_limit_is_enforced(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        path = f"/api/v1/workspaces/{created['id']}/members"

        for i in range(20):
            assert api_client.post(f"{path}?user_id=u_{i}").status_code == 200
        assert api_client.post(f"{path}?user_id=u_overflow").status_code == 403

    def test_updating_an_absent_member_is_not_found(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        response = api_client.patch(
            f"/api/v1/workspaces/{created['id']}/members/u_ghost?role=admin"
        )
        assert response.status_code == 404

    def test_removing_an_absent_member_is_not_found(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        assert api_client.delete(
            f"/api/v1/workspaces/{created['id']}/members/u_ghost"
        ).status_code == 404

    def test_invalid_role_on_update_is_rejected(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        path = f"/api/v1/workspaces/{created['id']}/members"
        api_client.post(f"{path}?user_id=u_1")

        assert api_client.patch(f"{path}/u_1?role=superuser").status_code == 422


class TestSettings:
    def test_settings_round_trip(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        path = f"/api/v1/workspaces/{created['id']}/settings"

        response = api_client.patch(path, json={"default_case_priority": "critical"})
        assert response.status_code == 200
        assert response.json()["default_case_priority"] == "critical"
        assert api_client.get(path).json()["default_case_priority"] == "critical"

    def test_partial_update_does_not_reset_other_fields(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        path = f"/api/v1/workspaces/{created['id']}/settings"

        api_client.patch(path, json={"default_case_priority": "high"})
        api_client.patch(path, json={"auto_assignment": False})

        settings = api_client.get(path).json()
        assert settings["default_case_priority"] == "high"
        assert settings["auto_assignment"] is False

    def test_invalid_priority_is_rejected(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        response = api_client.patch(
            f"/api/v1/workspaces/{created['id']}/settings",
            json={"default_case_priority": "catastrophic"},
        )
        assert response.status_code == 422

class TestCases:
    def test_unknown_workspace_cases_is_not_found(self, api_client):
        _as(ADMIN_A)
        assert api_client.get("/api/v1/workspaces/ws_missing/cases").status_code == 404

    def test_cross_tenant_cases_read_is_refused(self, api_client):
        created = _create(api_client)
        _as(ADMIN_B)
        assert api_client.get(f"/api/v1/workspaces/{created['id']}/cases").status_code == 404

    def test_cases_for_a_real_workspace(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        response = api_client.get(f"/api/v1/workspaces/{created['id']}/cases")
        assert response.status_code == 200
        assert response.json() == {"cases": [], "total": 0, "limit": 50}

    def test_cases_limit_is_bounded(self, api_client):
        created = _create(api_client)
        _as(ADMIN_A)
        path = f"/api/v1/workspaces/{created['id']}/cases"
        assert api_client.get(path, params={"limit": 0}).status_code == 422
        assert api_client.get(path, params={"limit": 1001}).status_code == 422
        assert api_client.get(path, params={"limit": 5}).json()["limit"] == 5
