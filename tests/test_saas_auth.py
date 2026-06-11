"""Tests for SaaS AuthService — MFA, user store injection, and tenant isolation.

Covers the stubs fixed in issue #1085:
- verify_mfa() uses per-user secret from UserStore (not hardcoded placeholder)
- authenticate_user() resolves credentials via UserStore
- Tenant isolation: two users in different orgs stay separate
"""

import pytest
import pyotp

from src.saas.auth.service import (
    AuthService,
    InMemoryUserStore,
    UserRecord,
)


def _make_service(users=None):
    store = InMemoryUserStore()
    for u in (users or []):
        store.add(u)
    return AuthService({"jwt_secret": "test-secret-only", "access_token_expiry": 3600}, user_store=store)


class TestVerifyMfa:
    def test_valid_totp_accepted(self):
        import pyotp
        secret = pyotp.random_base32()
        user = UserRecord(
            user_id="u1", organization_id="org_a", email="a@example.com",
            mfa_enabled=True, mfa_secret=secret,
        )
        svc = _make_service([user])
        totp_token = pyotp.TOTP(secret).now()
        result = svc.verify_mfa("u1", mfa_token="any", token=totp_token)
        assert result.success is True
        assert result.organization_id == "org_a"

    def test_invalid_totp_rejected(self):
        secret = pyotp.random_base32()
        user = UserRecord(
            user_id="u2", organization_id="org_b", email="b@example.com",
            mfa_enabled=True, mfa_secret=secret,
        )
        svc = _make_service([user])
        result = svc.verify_mfa("u2", mfa_token="any", token="000000")
        assert result.success is False
        assert "Invalid MFA token" in result.error

    def test_unknown_user_rejected(self):
        svc = _make_service()
        result = svc.verify_mfa("nonexistent", mfa_token="any", token="123456")
        assert result.success is False
        assert "not found" in result.error.lower()

    def test_mfa_not_configured_rejected(self):
        user = UserRecord(
            user_id="u3", organization_id="org_c", email="c@example.com",
            mfa_enabled=False, mfa_secret="",
        )
        svc = _make_service([user])
        result = svc.verify_mfa("u3", mfa_token="any", token="123456")
        assert result.success is False
        assert "not configured" in result.error.lower()

    def test_mfa_does_not_use_hardcoded_secret(self):
        """Ensure two users with different secrets cannot cross-verify."""
        secret_a = pyotp.random_base32()
        secret_b = pyotp.random_base32()
        user_a = UserRecord("ua", "org_a", "a@x.com", mfa_enabled=True, mfa_secret=secret_a)
        user_b = UserRecord("ub", "org_b", "b@x.com", mfa_enabled=True, mfa_secret=secret_b)
        svc = _make_service([user_a, user_b])
        token_for_a = pyotp.TOTP(secret_a).now()
        # token generated for user A must not authenticate user B
        result = svc.verify_mfa("ub", mfa_token="any", token=token_for_a)
        assert result.success is False


class TestAuthenticateUser:
    def test_valid_password_accepted(self):
        svc = _make_service()
        pw_hash = svc.hash_password("correct-password")
        user = UserRecord("u4", "org_d", "d@x.com", password_hash=pw_hash)
        svc.user_store.add(user)
        result = svc.authenticate_user("d@x.com", "correct-password")
        assert result.success is True
        assert result.organization_id == "org_d"

    def test_wrong_password_rejected(self):
        svc = _make_service()
        pw_hash = svc.hash_password("correct-password")
        user = UserRecord("u5", "org_e", "e@x.com", password_hash=pw_hash)
        svc.user_store.add(user)
        result = svc.authenticate_user("e@x.com", "wrong-password")
        assert result.success is False

    def test_unknown_email_rejected(self):
        svc = _make_service()
        result = svc.authenticate_user("nobody@x.com", "password")
        assert result.success is False

    def test_tenant_isolation(self):
        """Users in different orgs must resolve to their own organization_id."""
        svc = _make_service()
        for uid, org, email in [("u6", "org_f", "f@x.com"), ("u7", "org_g", "g@x.com")]:
            pw_hash = svc.hash_password("pass")
            svc.user_store.add(UserRecord(uid, org, email, password_hash=pw_hash))

        r_f = svc.authenticate_user("f@x.com", "pass")
        r_g = svc.authenticate_user("g@x.com", "pass")
        assert r_f.organization_id == "org_f"
        assert r_g.organization_id == "org_g"
        assert r_f.organization_id != r_g.organization_id


class TestJwtSecretConfig:
    def test_explicit_secret_used(self):
        svc = AuthService({"jwt_secret": "my-explicit-secret"})
        assert svc.jwt_secret == "my-explicit-secret"

    def test_no_secret_generates_random(self):
        """When no secret is configured a random one is generated (dev fallback)."""
        svc1 = AuthService({})
        svc2 = AuthService({})
        # Two services without config should each get their own random secret
        assert svc1.jwt_secret != svc2.jwt_secret
        assert len(svc1.jwt_secret) == 64  # 32 bytes hex
