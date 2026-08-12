"""Tests that wrong TOTP does not burn pending MFA tokens (#3286)."""

from __future__ import annotations

import pyotp

from src.saas.auth.service import (
    AuthService,
    InMemoryMFAPendingStore,
    InMemoryUserStore,
    UserRecord,
)


def _make_service(users=None):
    store = InMemoryUserStore()
    for u in users or []:
        store.add(u)
    return AuthService(
        {"jwt_secret": "test-secret-only", "access_token_expiry": 3600},
        user_store=store,
    )


class TestMFAPendingValidateConsume:
    def test_validate_does_not_consume(self):
        store = InMemoryMFAPendingStore()
        token = store.issue("u1")
        assert store.validate("u1", token) is True
        assert store.validate("u1", token) is True
        assert store.consume("u1", token) is True
        assert store.validate("u1", token) is False

    def test_consume_requires_match(self):
        store = InMemoryMFAPendingStore()
        token = store.issue("u1")
        assert store.consume("u1", "wrong") is False
        assert store.validate("u1", token) is True


class TestWrongTotpDoesNotBurnPending:
    def test_wrong_totp_keeps_pending_token_for_retry(self):
        secret = pyotp.random_base32()
        user = UserRecord(
            user_id="u_retry",
            organization_id="org_r",
            email="r@example.com",
            mfa_enabled=True,
            mfa_secret=secret,
        )
        svc = _make_service([user])
        mfa_token = svc.mfa_pending_store.issue("u_retry")

        bad = svc.verify_mfa("u_retry", mfa_token=mfa_token, token="000000")
        assert bad.success is False
        assert "Invalid MFA token" in (bad.error or "")

        # Pending session must still be usable with the correct TOTP.
        good = svc.verify_mfa(
            "u_retry",
            mfa_token=mfa_token,
            token=pyotp.TOTP(secret).now(),
        )
        assert good.success is True
        assert good.user_id == "u_retry"

    def test_success_consumes_pending_token(self):
        secret = pyotp.random_base32()
        user = UserRecord(
            user_id="u_once",
            organization_id="org_o",
            email="o@example.com",
            mfa_enabled=True,
            mfa_secret=secret,
        )
        svc = _make_service([user])
        mfa_token = svc.mfa_pending_store.issue("u_once")
        first = svc.verify_mfa(
            "u_once",
            mfa_token=mfa_token,
            token=pyotp.TOTP(secret).now(),
        )
        assert first.success is True
        second = svc.verify_mfa(
            "u_once",
            mfa_token=mfa_token,
            token=pyotp.TOTP(secret).now(),
        )
        assert second.success is False
        assert "MFA session" in (second.error or "")

    def test_forged_pending_token_still_rejected(self):
        secret = pyotp.random_base32()
        user = UserRecord(
            user_id="u_forge",
            organization_id="org_f",
            email="f@example.com",
            mfa_enabled=True,
            mfa_secret=secret,
        )
        svc = _make_service([user])
        result = svc.verify_mfa(
            "u_forge",
            mfa_token="forged",
            token=pyotp.TOTP(secret).now(),
        )
        assert result.success is False
        assert "MFA session" in (result.error or "")
