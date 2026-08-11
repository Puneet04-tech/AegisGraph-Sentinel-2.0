"""Tests that password-reset lockout does not lock login (#3285)."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from src.saas.auth.attempt_limiter import (
    InMemoryAttemptLimiter,
    SCOPE_ACCOUNT,
    SCOPE_PASSWORD_RESET,
)
from src.saas.auth.service import AuthResult, UserRecord
from src.saas.routes import auth as auth_routes
from src.saas.routes.auth import PasswordResetRequest, request_password_reset


def _run(coro):
    return asyncio.run(coro)


class TestPasswordResetScopeIsolation:
    def test_scope_constant_distinct_from_account(self):
        assert SCOPE_PASSWORD_RESET != SCOPE_ACCOUNT
        assert SCOPE_PASSWORD_RESET == "password_reset"

    def test_reset_failures_do_not_lock_account_scope(self):
        limiter = InMemoryAttemptLimiter(
            thresholds={
                SCOPE_ACCOUNT: 5,
                SCOPE_PASSWORD_RESET: 5,
            }
        )
        identity = "user@example.com"
        for _ in range(5):
            state = limiter.record_failure(identity, SCOPE_PASSWORD_RESET)
        assert state.locked is True
        assert limiter.check(identity, SCOPE_PASSWORD_RESET).locked is True
        # Login budget must remain open.
        account = limiter.check(identity, SCOPE_ACCOUNT)
        assert account.locked is False
        assert account.failures == 0

    def test_account_failures_do_not_lock_reset_scope(self):
        limiter = InMemoryAttemptLimiter(
            thresholds={
                SCOPE_ACCOUNT: 5,
                SCOPE_PASSWORD_RESET: 5,
            }
        )
        identity = "user@example.com"
        for _ in range(5):
            limiter.record_failure(identity, SCOPE_ACCOUNT)
        assert limiter.check(identity, SCOPE_ACCOUNT).locked is True
        assert limiter.check(identity, SCOPE_PASSWORD_RESET).locked is False

    def test_reset_endpoint_uses_password_reset_scope_only(self):
        limiter = InMemoryAttemptLimiter(
            thresholds={
                SCOPE_ACCOUNT: 5,
                SCOPE_PASSWORD_RESET: 5,
            }
        )
        store = MagicMock()
        store.get_by_email.return_value = None
        service = MagicMock()
        service.attempt_limiter = limiter
        service.user_store = store

        with patch.object(auth_routes, "_get_auth_service", return_value=service):
            for _ in range(5):
                result = _run(
                    request_password_reset(
                        PasswordResetRequest(email="user@example.com")
                    )
                )
                assert result["success"] is True

            with pytest.raises(HTTPException) as exc:
                _run(
                    request_password_reset(
                        PasswordResetRequest(email="user@example.com")
                    )
                )
            assert exc.value.status_code == 429

        assert limiter.check("user@example.com", SCOPE_PASSWORD_RESET).locked is True
        assert limiter.check("user@example.com", SCOPE_ACCOUNT).locked is False

    def test_login_still_possible_after_reset_lockout(self):
        """Spraying /password/reset must not lock authenticate_user budget."""
        from src.saas.auth.service import AuthService, InMemoryUserStore

        limiter = InMemoryAttemptLimiter(
            thresholds={
                SCOPE_ACCOUNT: 5,
                SCOPE_PASSWORD_RESET: 5,
            }
        )
        store = InMemoryUserStore()
        svc = AuthService({"jwt_secret": "test-secret"}, user_store=store)
        # Base tree may omit limiter wiring; attach explicitly for this proof.
        svc.attempt_limiter = limiter
        if not hasattr(svc, "revocation_store"):
            from src.saas.auth.revocation import InMemoryTokenRevocationStore

            svc.revocation_store = InMemoryTokenRevocationStore()

        password = "correct-password-1"
        store.add(
            UserRecord(
                "u1",
                "org1",
                "user@example.com",
                password_hash=svc.hash_password(password),
            )
        )

        for _ in range(5):
            limiter.record_failure("user@example.com", SCOPE_PASSWORD_RESET)
        assert limiter.check("user@example.com", SCOPE_PASSWORD_RESET).locked is True

        result = svc.authenticate_user("user@example.com", password)
        assert result.success is True
        assert result.rate_limited is False
