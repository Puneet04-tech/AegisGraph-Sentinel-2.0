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
from src.exceptions import AuthenticationError


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
        # Simulate the login step issuing a pending-MFA token.
        mfa_token = svc.mfa_pending_store.issue("u1")
        totp_token = pyotp.TOTP(secret).now()
        result = svc.verify_mfa("u1", mfa_token=mfa_token, token=totp_token)
        assert result.success is True
        assert result.organization_id == "org_a"

    def test_invalid_totp_rejected(self):
        secret = pyotp.random_base32()
        user = UserRecord(
            user_id="u2", organization_id="org_b", email="b@example.com",
            mfa_enabled=True, mfa_secret=secret,
        )
        svc = _make_service([user])
        mfa_token = svc.mfa_pending_store.issue("u2")
        result = svc.verify_mfa("u2", mfa_token=mfa_token, token="000000")
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
        # Issue a valid pending-MFA token for ub so the check reaches TOTP
        # verification — the point is that A's TOTP must not verify for B.
        mfa_token = svc.mfa_pending_store.issue("ub")
        token_for_a = pyotp.TOTP(secret_a).now()
        result = svc.verify_mfa("ub", mfa_token=mfa_token, token=token_for_a)
        assert result.success is False
        
    def test_missing_mfa_token_rejected_even_with_valid_totp(self):
        """The core fix (#1388): a correct TOTP must NOT authenticate without
        a valid pending-MFA token from the login step."""
        secret = pyotp.random_base32()
        user = UserRecord(
            user_id="u_bind", organization_id="org_x", email="x@example.com",
            mfa_enabled=True, mfa_secret=secret,
        )
        svc = _make_service([user])
        totp_token = pyotp.TOTP(secret).now()
        # No token issued — simulates calling /mfa/verify without /login.
        result = svc.verify_mfa("u_bind", mfa_token="forged", token=totp_token)
        assert result.success is False
        assert "MFA session" in result.error

    def test_mfa_token_is_single_use(self):
        """A pending-MFA token must not be reusable after a successful verify."""
        secret = pyotp.random_base32()
        user = UserRecord(
            user_id="u_once", organization_id="org_y", email="y@example.com",
            mfa_enabled=True, mfa_secret=secret,
        )
        svc = _make_service([user])
        mfa_token = svc.mfa_pending_store.issue("u_once")
        first = svc.verify_mfa("u_once", mfa_token=mfa_token,
                            token=pyotp.TOTP(secret).now())
        assert first.success is True
        # Reusing the same token must fail.
        second = svc.verify_mfa("u_once", mfa_token=mfa_token, 
                            token=pyotp.TOTP(secret).now())
        assert second.success is False
        assert "MFA session" in second.error


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

    def test_missing_configuration_fails_closed(self):
        svc = AuthService({"jwt_secret": "test-secret-only"})
        result = svc.authenticate_user("nobody@x.com", "password")
        assert result.success is False
        assert "not configured" in result.error.lower()

    def test_runtime_credentials_from_env_are_loaded(self, monkeypatch):
        svc = _make_service()
        admin_hash = svc.hash_password("admin-password")
        monkeypatch.setenv("ADMIN_USERNAME", "admin@example.com")
        monkeypatch.setenv("ADMIN_PASSWORD_HASH", admin_hash)
        runtime_service = AuthService({"jwt_secret": "test-secret-only"})
        result = runtime_service.authenticate_user("admin@example.com", "admin-password")
        assert result.success is True
        assert result.email == "admin@example.com"
        assert result.organization_id == "administration"
        assert result.user_id == "admin_user"

    def test_operator_role_is_assigned_from_runtime_credentials(self, monkeypatch):
        svc = _make_service()
        operator_hash = svc.hash_password("operator-password")
        monkeypatch.setenv("OPERATOR_USERNAME", "operator@example.com")
        monkeypatch.setenv("OPERATOR_PASSWORD_HASH", operator_hash)
        runtime_service = AuthService({"jwt_secret": "test-secret-only"})
        result = runtime_service.authenticate_user("operator@example.com", "operator-password")
        assert result.success is True
        assert result.email == "operator@example.com"
        assert result.organization_id == "operations"
        assert result.user_id == "operator_user"

    def test_invalid_hash_format_is_ignored(self, monkeypatch):
        monkeypatch.setenv("ADMIN_USERNAME", "admin@example.com")
        monkeypatch.setenv("ADMIN_PASSWORD_HASH", "plaintext-not-allowed")
        runtime_service = AuthService({"jwt_secret": "test-secret-only"})
        result = runtime_service.authenticate_user("admin@example.com", "plaintext-not-allowed")
        assert result.success is False
        assert "not configured" in result.error.lower()

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


class TestLogoutRevocation:
    def test_logout_revokes_current_token(self):
        svc = _make_service()
        pw_hash = svc.hash_password("logout-password")
        user = UserRecord("u_logout", "org_logout", "logout@example.com", password_hash=pw_hash)
        svc.user_store.add(user)
        result = svc.authenticate_user("logout@example.com", "logout-password")
        assert result.success is True
        payload = svc.verify_token(result.access_token)
        assert payload is not None
        svc.revoke_token_id(payload.jti)
        with pytest.raises(AuthenticationError):
            svc.verify_token(result.access_token)
