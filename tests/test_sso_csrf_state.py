"""Tests for SSO OAuth CSRF state (#3283)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from src.saas.auth.service import AuthProvider, AuthResult
from src.saas.routes import auth as auth_routes
from src.saas.routes.auth import (
    InMemorySSOStateStore,
    SSOCallbackRequest,
    sso_authorize,
    sso_callback,
)


def _run(coro):
    return asyncio.run(coro)


class TestInMemorySSOStateStore:
    def test_issue_and_consume_matching_provider(self):
        store = InMemorySSOStateStore(ttl_seconds=60)
        state = store.issue("google", "https://app.example.com/cb")
        assert store.consume(state, "google") == "https://app.example.com/cb"
        assert store.consume(state, "google") is None

    def test_issue_without_redirect_uri_consumes_as_empty_string(self):
        store = InMemorySSOStateStore(ttl_seconds=60)
        state = store.issue("google")
        assert store.consume(state, "google") == ""

    def test_provider_mismatch_rejected(self):
        store = InMemorySSOStateStore(ttl_seconds=60)
        state = store.issue("google")
        assert store.consume(state, "okta") is None
        assert store.consume(state, "google") is None

    def test_unknown_state_rejected(self):
        store = InMemorySSOStateStore()
        assert store.consume("missing", "google") is None

    def test_empty_state_rejected(self):
        store = InMemorySSOStateStore()
        assert store.consume("", "google") is None

    def test_expired_state_rejected(self):
        store = InMemorySSOStateStore(ttl_seconds=60)
        state = store.issue("azure_ad", "https://app.example.com/cb")
        provider, redirect_uri, _ = store._pending[state]
        store._pending[state] = (
            provider,
            redirect_uri,
            datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        assert store.consume(state, "azure_ad") is None


class TestSSOAuthorizeCallbackState:
    def test_authorize_mints_state_bound_to_provider(self):
        store = InMemorySSOStateStore()
        provider_obj = MagicMock()
        provider_obj.get_authorization_url.return_value = (
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=x"
        )
        service = MagicMock()
        service.sso_providers = {AuthProvider.GOOGLE: provider_obj}

        with patch.object(auth_routes, "_sso_state_store", store), patch.object(
            auth_routes, "_get_auth_service", return_value=service
        ), patch.object(
            auth_routes, "_SSO_REDIRECT_ALLOWLIST", ["https://app.example.com/cb"]
        ):
            result = _run(
                sso_authorize(
                    provider=AuthProvider.GOOGLE,
                    redirect_uri="https://app.example.com/cb",
                    current_user={"user_id": "u1"},
                )
            )

        assert "state=" in result["authorization_url"]
        assert result["state"]
        assert store.consume(result["state"], "google") == "https://app.example.com/cb"

    def test_callback_uses_stored_redirect_uri_for_exchange(self):
        store = InMemorySSOStateStore()
        state = store.issue("google", "https://app.example.com/cb")
        service = MagicMock()
        service.authenticate_sso.return_value = AuthResult(
            success=True,
            user_id="u1",
            organization_id="org1",
            role="member",
            access_token="access",
            refresh_token="refresh",
        )

        with patch.object(auth_routes, "_sso_state_store", store), patch.object(
            auth_routes, "_get_auth_service", return_value=service
        ):
            response = _run(
                sso_callback(
                    SSOCallbackRequest(
                        code="auth-code",
                        state=state,
                        provider=AuthProvider.GOOGLE,
                    )
                )
            )

        assert response.access_token == "access"
        service.authenticate_sso.assert_called_once_with(
            provider=AuthProvider.GOOGLE,
            code="auth-code",
            redirect_uri="https://app.example.com/cb",
        )

    def test_callback_rejects_invalid_state(self):
        store = InMemorySSOStateStore()
        with patch.object(auth_routes, "_sso_state_store", store):
            with pytest.raises(HTTPException) as exc:
                _run(
                    sso_callback(
                        SSOCallbackRequest(
                            code="abc",
                            state="forged",
                            provider=AuthProvider.GOOGLE,
                        )
                    )
                )
        assert exc.value.status_code == 401
        assert "state" in exc.value.detail.lower()

    def test_callback_consumes_valid_state_then_authenticates(self):
        store = InMemorySSOStateStore()
        state = store.issue("google", "https://app.example.com/cb")
        service = MagicMock()
        service.authenticate_sso.return_value = AuthResult(
            success=True,
            user_id="u1",
            organization_id="org1",
            role="member",
            access_token="access",
            refresh_token="refresh",
        )

        with patch.object(auth_routes, "_sso_state_store", store), patch.object(
            auth_routes, "_get_auth_service", return_value=service
        ):
            response = _run(
                sso_callback(
                    SSOCallbackRequest(
                        code="auth-code",
                        state=state,
                        provider=AuthProvider.GOOGLE,
                    )
                )
            )

        assert response.access_token == "access"
        assert store.consume(state, "google") is None
        service.authenticate_sso.assert_called_once_with(
            provider=AuthProvider.GOOGLE,
            code="auth-code",
            redirect_uri="https://app.example.com/cb",
        )

    def test_callback_rejects_provider_mismatch(self):
        store = InMemorySSOStateStore()
        state = store.issue("google")
        with patch.object(auth_routes, "_sso_state_store", store):
            with pytest.raises(HTTPException) as exc:
                _run(
                    sso_callback(
                        SSOCallbackRequest(
                            code="auth-code",
                            state=state,
                            provider=AuthProvider.OKTA,
                        )
                    )
                )
        assert exc.value.status_code == 401
