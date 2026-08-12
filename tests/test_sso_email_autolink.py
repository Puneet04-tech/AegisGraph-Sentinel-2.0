"""Tests for SSO email auto-link takeover guard (#3284)."""

from __future__ import annotations

import pytest

from src.exceptions import AuthenticationError
from src.saas.auth.service import (
    AuthProvider,
    AuthService,
    InMemoryUserStore,
    UserRecord,
    _sso_email_is_verified,
)


def _service_with_user(email: str = "victim@example.com") -> AuthService:
    store = InMemoryUserStore()
    store.add(UserRecord("u_victim", "org_victim", email))
    svc = AuthService({"jwt_secret": "test-secret"}, user_store=store)
    return svc


class FakeSSO:
    def __init__(self, user_info):
        self._user_info = user_info

    def exchange_code(self, code, redirect_uri):
        return {"access_token": "tok"}

    def get_user_info(self, access_token):
        return self._user_info


class TestEmailVerifiedHelper:
    def test_email_verified_true(self):
        assert _sso_email_is_verified({"email_verified": True}) is True

    def test_verified_email_true(self):
        assert _sso_email_is_verified({"verified_email": True}) is True

    def test_string_true_accepted(self):
        assert _sso_email_is_verified({"email_verified": "true"}) is True

    def test_missing_or_false_rejected(self):
        assert _sso_email_is_verified({}) is False
        assert _sso_email_is_verified({"email_verified": False}) is False
        assert _sso_email_is_verified({"email_verified": "false"}) is False


class TestFindOrCreateSsoUser:
    def test_refuses_link_when_unverified_and_email_exists(self):
        store = InMemoryUserStore()
        store.add(UserRecord("u1", "org1", "taken@example.com"))
        with pytest.raises(AuthenticationError, match="not verified"):
            store.find_or_create_sso_user(
                "google",
                {"email": "taken@example.com", "email_verified": False},
            )

    def test_links_when_verified_and_email_exists(self):
        store = InMemoryUserStore()
        store.add(UserRecord("u1", "org1", "taken@example.com"))
        user_id, org_id = store.find_or_create_sso_user(
            "google",
            {"email": "taken@example.com", "email_verified": True},
        )
        assert user_id == "u1"
        assert org_id == "org1"

    def test_creates_new_user_when_email_unknown_even_if_unverified(self):
        store = InMemoryUserStore()
        user_id, org_id = store.find_or_create_sso_user(
            "google",
            {"email": "new@example.com"},
        )
        assert store.get_by_id(user_id) is not None
        assert store.get_by_email("new@example.com").organization_id == org_id


class TestAuthenticateSsoAutoLink:
    def test_authenticate_sso_errors_on_unverified_existing_email(self):
        svc = _service_with_user("victim@example.com")
        svc.sso_providers[AuthProvider.GOOGLE] = FakeSSO(
            {"email": "victim@example.com", "email_verified": False}
        )
        result = svc.authenticate_sso(
            AuthProvider.GOOGLE, "code", "https://app/cb"
        )
        assert result.success is False
        assert "not verified" in (result.error or "").lower()

    def test_authenticate_sso_links_when_verified(self):
        svc = _service_with_user("victim@example.com")
        svc.sso_providers[AuthProvider.GOOGLE] = FakeSSO(
            {"email": "victim@example.com", "email_verified": True}
        )
        result = svc.authenticate_sso(
            AuthProvider.GOOGLE, "code", "https://app/cb"
        )
        assert result.success is True
        assert result.user_id == "u_victim"
        assert result.organization_id == "org_victim"

    def test_authenticate_sso_creates_when_unverified_new_email(self):
        svc = _service_with_user("other@example.com")
        svc.sso_providers[AuthProvider.GOOGLE] = FakeSSO(
            {"email": "brand-new@example.com"}
        )
        result = svc.authenticate_sso(
            AuthProvider.GOOGLE, "code", "https://app/cb"
        )
        assert result.success is True
        assert result.email == "brand-new@example.com"
        assert result.user_id != "u_victim"
