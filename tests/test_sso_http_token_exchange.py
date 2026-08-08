"""Tests for real SSO token exchange (#3282).

Providers must call the IdP token/userinfo endpoints over HTTP and fail
closed on errors. Mock tokens are not accepted.
"""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from src.exceptions import AuthenticationError
from src.saas.auth.service import (
    AuthProvider,
    AuthService,
    AzureADSSOProvider,
    GoogleSSOProvider,
    InMemoryUserStore,
    OktaSSOProvider,
    UserRecord,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unsigned_jwt(claims: dict) -> str:
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    return f"{header}.{payload}."


def _json_response(payload: dict, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code,
        json=payload,
        request=httpx.Request("POST", "https://example.test/token"),
    )


class TestProviderConfigFailsClosed:
    def test_google_requires_credentials(self):
        with pytest.raises(ValueError, match="client_id"):
            GoogleSSOProvider({})

    def test_okta_requires_domain(self):
        with pytest.raises(ValueError, match="okta_domain"):
            OktaSSOProvider(
                {"client_id": "id", "client_secret": "secret"}
            )

    def test_azure_accepts_tenant_default(self):
        provider = AzureADSSOProvider(
            {"client_id": "id", "client_secret": "secret"}
        )
        assert "common" in provider.token_url


class TestGoogleTokenExchange:
    def test_exchange_posts_to_google_token_endpoint(self):
        provider = GoogleSSOProvider(
            {"client_id": "gid", "client_secret": "gsecret"}
        )
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        mock_client.post.return_value = _json_response(
            {"access_token": "at-1", "id_token": "idt-1"}
        )

        with patch("httpx.Client", return_value=mock_client):
            tokens = provider.exchange_code("auth-code", "https://app/cb")

        assert tokens["access_token"] == "at-1"
        assert tokens["id_token"] == "idt-1"
        kwargs = mock_client.post.call_args
        assert kwargs.args[0] == "https://oauth2.googleapis.com/token"
        assert kwargs.kwargs["data"]["code"] == "auth-code"
        assert kwargs.kwargs["data"]["client_secret"] == "gsecret"

    def test_exchange_fails_closed_on_http_error(self):
        provider = GoogleSSOProvider(
            {"client_id": "gid", "client_secret": "gsecret"}
        )
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        mock_client.post.side_effect = httpx.ConnectError("boom")

        with patch("httpx.Client", return_value=mock_client):
            with pytest.raises(AuthenticationError, match="token exchange"):
                provider.exchange_code("auth-code", "https://app/cb")

    def test_exchange_fails_closed_on_error_status(self):
        provider = GoogleSSOProvider(
            {"client_id": "gid", "client_secret": "gsecret"}
        )
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        mock_client.post.return_value = _json_response(
            {"error": "invalid_grant"}, status_code=400
        )

        with patch("httpx.Client", return_value=mock_client):
            with pytest.raises(AuthenticationError, match="token exchange"):
                provider.exchange_code("bad", "https://app/cb")

    def test_get_user_info_calls_userinfo(self):
        provider = GoogleSSOProvider(
            {"client_id": "gid", "client_secret": "gsecret"}
        )
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        mock_client.get.return_value = httpx.Response(
            200,
            json={
                "sub": "g-sub",
                "email": "user@gmail.com",
                "email_verified": True,
                "name": "User",
            },
            request=httpx.Request("GET", provider.userinfo_url),
        )

        with patch("httpx.Client", return_value=mock_client):
            info = provider.get_user_info("access-token")

        assert info["email"] == "user@gmail.com"
        assert mock_client.get.call_args.args[0] == provider.userinfo_url

    def test_get_user_info_falls_back_to_id_token(self):
        provider = GoogleSSOProvider(
            {"client_id": "gid", "client_secret": "gsecret"}
        )
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        mock_client.get.return_value = httpx.Response(
            401,
            json={"error": "invalid_token"},
            request=httpx.Request("GET", provider.userinfo_url),
        )
        id_token = _unsigned_jwt(
            {"sub": "g-sub", "email": "from-id@example.com"}
        )

        with patch("httpx.Client", return_value=mock_client):
            info = provider.get_user_info("access-token", id_token=id_token)

        assert info["email"] == "from-id@example.com"


class TestOktaAndAzureEndpoints:
    def test_okta_uses_configured_domain(self):
        provider = OktaSSOProvider(
            {
                "client_id": "oid",
                "client_secret": "osecret",
                "okta_domain": "https://example.okta.com",
            }
        )
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        mock_client.post.return_value = _json_response(
            {"access_token": "okta-at"}
        )

        with patch("httpx.Client", return_value=mock_client):
            tokens = provider.exchange_code("c", "https://app/cb")

        assert tokens["access_token"] == "okta-at"
        assert mock_client.post.call_args.args[0] == (
            "https://example.okta.com/oauth2/v1/token"
        )

    def test_azure_uses_tenant_token_url(self):
        provider = AzureADSSOProvider(
            {
                "client_id": "aid",
                "client_secret": "asecret",
                "tenant_id": "tenant-1",
            }
        )
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        mock_client.post.return_value = _json_response(
            {"access_token": "az-at"}
        )

        with patch("httpx.Client", return_value=mock_client):
            tokens = provider.exchange_code("c", "https://app/cb")

        assert tokens["access_token"] == "az-at"
        assert (
            mock_client.post.call_args.args[0]
            == "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
        )


class TestAuthenticateSsoFailClosed:
    def test_authenticate_sso_returns_error_on_exchange_failure(self):
        store = InMemoryUserStore()
        store.add(UserRecord("u1", "org1", "user@example.com"))
        svc = AuthService({"jwt_secret": "test-secret"}, user_store=store)
        svc.add_sso_provider(
            AuthProvider.GOOGLE,
            {"client_id": "gid", "client_secret": "gsecret"},
        )

        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        mock_client.post.return_value = _json_response(
            {"error": "invalid_grant"}, status_code=400
        )

        with patch("httpx.Client", return_value=mock_client):
            result = svc.authenticate_sso(
                AuthProvider.GOOGLE, "bad-code", "https://app/cb"
            )

        assert result.success is False
        assert "token exchange" in (result.error or "").lower()

    def test_authenticate_sso_success_with_mocked_http(self):
        store = InMemoryUserStore()
        store.add(UserRecord("u1", "org1", "user@example.com"))
        svc = AuthService({"jwt_secret": "test-secret"}, user_store=store)
        # Restore limiter/revocation if missing so auth result path is stable.
        if not hasattr(svc, "attempt_limiter"):
            from src.saas.auth.attempt_limiter import InMemoryAttemptLimiter
            from src.saas.auth.revocation import InMemoryTokenRevocationStore

            svc.attempt_limiter = InMemoryAttemptLimiter()
            svc.revocation_store = InMemoryTokenRevocationStore()

        svc.add_sso_provider(
            AuthProvider.GOOGLE,
            {"client_id": "gid", "client_secret": "gsecret"},
        )

        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.__exit__.return_value = False
        mock_client.post.return_value = _json_response(
            {"access_token": "at", "id_token": "idt"}
        )
        mock_client.get.return_value = httpx.Response(
            200,
            json={"sub": "g1", "email": "user@example.com", "email_verified": True},
            request=httpx.Request(
                "GET", "https://openidconnect.googleapis.com/v1/userinfo"
            ),
        )

        with patch("httpx.Client", return_value=mock_client):
            result = svc.authenticate_sso(
                AuthProvider.GOOGLE, "good-code", "https://app/cb"
            )

        assert result.success is True
        assert result.user_id == "u1"
        assert result.organization_id == "org1"
