"""SSO redirect allowlist must fail closed (Issue #3508).

When ``OAUTH_REDIRECT_URIS`` is unset the allowlist used to be empty, and the
``if _SSO_REDIRECT_ALLOWLIST and ...`` guard short-circuited, accepting any
redirect target (open redirect / OAuth code interception). These tests pin the
unconditional enforcement and the empty-allowlist -> SSO disabled behaviour.
"""

import asyncio

import pytest
from fastapi import HTTPException

import src.saas.routes.auth as auth_routes
from src.saas.auth.service import AuthProvider

ALLOWED = "https://app.example.com/cb"


class FakeSSOProvider:
    def __init__(self):
        self.redirect_uri = None

    def get_authorization_url(self):
        return "https://accounts.google.com/o/oauth2/v2/auth?client_id=x"


class FakeAuthService:
    sso_providers = {AuthProvider.GOOGLE: FakeSSOProvider()}


class FakeStateStore:
    def issue(self, provider, redirect_uri=""):
        return "state-123"


def _authorize(redirect_uri: str):
    return asyncio.run(
        auth_routes.sso_authorize(
            provider=AuthProvider.GOOGLE,
            redirect_uri=redirect_uri,
            current_user={"user_id": "u1"},
        )
    )


class TestSSORedirectAllowlist:
    def test_empty_allowlist_disables_sso_authorize(self, monkeypatch):
        monkeypatch.setattr(auth_routes, "_SSO_REDIRECT_ALLOWLIST", [])
        with pytest.raises(HTTPException) as exc:
            _authorize(ALLOWED)
        assert exc.value.status_code == 503
        assert "OAUTH_REDIRECT_URIS" in exc.value.detail

    def test_out_of_allowlist_uri_is_rejected(self, monkeypatch):
        monkeypatch.setattr(auth_routes, "_SSO_REDIRECT_ALLOWLIST", [ALLOWED])
        with pytest.raises(HTTPException) as exc:
            _authorize("https://attacker.example/cb")
        assert exc.value.status_code == 400

    def test_allowed_uri_is_accepted(self, monkeypatch):
        monkeypatch.setattr(auth_routes, "_SSO_REDIRECT_ALLOWLIST", [ALLOWED])
        monkeypatch.setattr(auth_routes, "_get_auth_service", lambda: FakeAuthService())
        monkeypatch.setattr(auth_routes, "_sso_state_store", FakeStateStore())

        result = _authorize(ALLOWED)
        assert result["state"] == "state-123"
        assert "state=state-123" in result["authorization_url"]
