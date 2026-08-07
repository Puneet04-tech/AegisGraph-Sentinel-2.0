"""Tests for OAuth2 scope allow-list enforcement."""

from urllib.parse import parse_qs, urlparse

from src.identity_federation.oauth_provider import OAuthProvider
from src.identity_federation.store import IdentityFederationStore


def _provider_with_client(scopes=None) -> OAuthProvider:
    store = IdentityFederationStore()
    oauth = OAuthProvider(store, "https://aegisgraph.example.com")
    oauth.register_client(
        client_id="client-1",
        client_secret="secret-1",
        redirect_uris=["https://app.example.com/callback"],
        scopes=scopes or ["openid", "profile"],
    )
    return oauth


class TestOAuthScopeAllowlist:
    def test_client_credentials_rejects_unknown_scope(self):
        oauth = _provider_with_client()
        response = oauth.token(
            grant_type="client_credentials",
            client_id="client-1",
            client_secret="secret-1",
            scope="openid admin",
        )
        assert response.success is False
        assert response.error == "invalid_scope"
        assert "admin" in (response.error_description or "")

    def test_client_credentials_allows_registered_scopes(self):
        oauth = _provider_with_client()
        response = oauth.token(
            grant_type="client_credentials",
            client_id="client-1",
            client_secret="secret-1",
            scope="openid profile",
        )
        assert response.success is True
        assert response.metadata["scope"] == "openid profile"

    def test_authorization_code_rejects_escalated_scope_at_authorize(self):
        oauth = _provider_with_client()
        response = oauth.authorize(
            client_id="client-1",
            redirect_uri="https://app.example.com/callback",
            response_type="code",
            scope="openid admin",
        )
        assert response.success is False
        assert response.error == "invalid_scope"

    def test_authorization_code_token_rejects_stored_escalated_scope(self):
        oauth = _provider_with_client()
        authorize = oauth.authorize(
            client_id="client-1",
            redirect_uri="https://app.example.com/callback",
            response_type="code",
            scope="openid",
        )
        assert authorize.success is True
        code = parse_qs(urlparse(authorize.redirect_url).query)["code"][0]

        # Tamper with stored auth code scopes to simulate escalation
        oauth._auth_codes[code]["scope"] = "openid admin"

        response = oauth.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri="https://app.example.com/callback",
            client_id="client-1",
            client_secret="secret-1",
        )
        assert response.success is False
        assert response.error == "invalid_scope"
