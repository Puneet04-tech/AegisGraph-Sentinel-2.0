from __future__ import annotations

import pytest

from src.api.main import app
from src.saas.routes import users as users_routes
from src.saas.routes.auth import get_current_user


def _override_user(user):
    app.dependency_overrides[get_current_user] = lambda: user


def _clear_overrides():
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture(autouse=True)
def _reset_users_state():
    users_routes._USER_STORE.clear()
    users_routes._AUDIT_LOG.clear()
    yield
    users_routes._USER_STORE.clear()
    users_routes._AUDIT_LOG.clear()
    _clear_overrides()


def test_anonymous_request_is_rejected(api_client):
    response = api_client.get("/api/v1/users/user-1")
    assert response.status_code == 401


def test_member_cannot_create_user(api_client):
    _override_user({"user_id": "member-1", "organization_id": "org-1", "role": "member"})
    response = api_client.post(
        "/api/v1/users/",
        json={
            "email": "new@example.com",
            "password": "StrongPass123!",
            "role": "member",
        },
    )
    assert response.status_code == 403


def test_admin_create_user_hashes_password_and_assigns_tenant(api_client):
    _override_user({"user_id": "admin-1", "organization_id": "org-1", "role": "admin"})
    response = api_client.post(
        "/api/v1/users/",
        json={
            "email": "new@example.com",
            "full_name": "New User",
            "username": "new_user",
            "password": "StrongPass123!",
            "role": "member",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "new@example.com"
    assert body["role"] == "member"
    created = users_routes._USER_STORE[body["id"]]
    assert created["tenant_id"] == "org-1"
    assert created["password_hash"] != "StrongPass123!"
    assert created["password_hash"].startswith("$2")


def test_invalid_role_is_rejected(api_client):
    _override_user({"user_id": "admin-1", "organization_id": "org-1", "role": "admin"})
    response = api_client.post(
        "/api/v1/users/",
        json={
            "email": "new@example.com",
            "password": "StrongPass123!",
            "role": "owner-orbiter",
        },
    )
    assert response.status_code == 422


def test_owner_can_read_own_record(api_client):
    user_id = "user-owner"
    users_routes._USER_STORE[user_id] = {
        "id": user_id,
        "tenant_id": "org-1",
        "email": "owner@example.com",
        "full_name": "Owner",
        "username": "owner",
        "phone": None,
        "avatar_url": None,
        "role": "member",
        "is_active": True,
        "email_verified": False,
        "mfa_enabled": False,
        "last_login": None,
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        "password_hash": "hash",
    }
    _override_user({"user_id": user_id, "organization_id": "org-1", "role": "member"})
    response = api_client.get(f"/api/v1/users/{user_id}")
    assert response.status_code == 200
    assert "password_hash" not in response.text


def test_member_cannot_read_other_user(api_client):
    users_routes._USER_STORE["user-1"] = {
        "id": "user-1",
        "tenant_id": "org-1",
        "email": "owner@example.com",
        "full_name": "Owner",
        "username": "owner",
        "phone": None,
        "avatar_url": None,
        "role": "member",
        "is_active": True,
        "email_verified": False,
        "mfa_enabled": False,
        "last_login": None,
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        "password_hash": "hash",
    }
    _override_user({"user_id": "user-2", "organization_id": "org-1", "role": "member"})
    response = api_client.get("/api/v1/users/user-1")
    assert response.status_code == 403


def test_cross_tenant_access_is_rejected(api_client):
    users_routes._USER_STORE["user-1"] = {
        "id": "user-1",
        "tenant_id": "org-1",
        "email": "owner@example.com",
        "full_name": "Owner",
        "username": "owner",
        "phone": None,
        "avatar_url": None,
        "role": "member",
        "is_active": True,
        "email_verified": False,
        "mfa_enabled": False,
        "last_login": None,
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        "password_hash": "hash",
    }
    _override_user({"user_id": "admin-1", "organization_id": "org-2", "role": "admin"})
    response = api_client.get("/api/v1/users/user-1")
    assert response.status_code == 404


def test_self_update_allowed_and_admin_update_allowed(api_client):
    users_routes._USER_STORE["user-1"] = {
        "id": "user-1",
        "tenant_id": "org-1",
        "email": "owner@example.com",
        "full_name": "Owner",
        "username": "owner",
        "phone": None,
        "avatar_url": None,
        "role": "member",
        "is_active": True,
        "email_verified": False,
        "mfa_enabled": False,
        "last_login": None,
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        "password_hash": "hash",
    }
    _override_user({"user_id": "user-1", "organization_id": "org-1", "role": "member"})
    response = api_client.patch("/api/v1/users/user-1", json={"full_name": "Updated"})
    assert response.status_code == 200
    assert response.json()["full_name"] == "Updated"

    _override_user({"user_id": "admin-1", "organization_id": "org-1", "role": "admin"})
    response = api_client.patch("/api/v1/users/user-1", json={"full_name": "Admin Updated"})
    assert response.status_code == 200
    assert response.json()["full_name"] == "Admin Updated"


def test_unauthorized_deletion_blocked(api_client):
    users_routes._USER_STORE["user-1"] = {
        "id": "user-1",
        "tenant_id": "org-1",
        "email": "owner@example.com",
        "full_name": "Owner",
        "username": "owner",
        "phone": None,
        "avatar_url": None,
        "role": "member",
        "is_active": True,
        "email_verified": False,
        "mfa_enabled": False,
        "last_login": None,
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        "password_hash": "hash",
    }
    _override_user({"user_id": "member-1", "organization_id": "org-1", "role": "member"})
    response = api_client.delete("/api/v1/users/user-1")
    assert response.status_code == 403


def test_admin_deletion_and_audit_logging(api_client):
    users_routes._USER_STORE["user-1"] = {
        "id": "user-1",
        "tenant_id": "org-1",
        "email": "owner@example.com",
        "full_name": "Owner",
        "username": "owner",
        "phone": None,
        "avatar_url": None,
        "role": "member",
        "is_active": True,
        "email_verified": False,
        "mfa_enabled": False,
        "last_login": None,
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        "password_hash": "hash",
    }
    _override_user({"user_id": "admin-1", "organization_id": "org-1", "role": "admin"})
    response = api_client.delete("/api/v1/users/user-1")
    assert response.status_code == 204
    assert users_routes._USER_STORE["user-1"]["is_active"] is False
    assert users_routes._AUDIT_LOG[-1]["action"] == "user_deleted"


def test_invalid_jwt_rejected(api_client):
    response = api_client.get("/api/v1/users/user-1", headers={"Authorization": "Bearer not-a-jwt"})
    assert response.status_code == 401

