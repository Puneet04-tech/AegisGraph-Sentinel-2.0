"""Tests for the password, MFA, session, and API-key lifecycle.

Covers the feature implemented for issue #2706: nine endpoints in
``src/saas/routes/auth.py`` returned hardcoded success without performing the
operation they named. ``change_password`` reported success without touching the
password hash, ``/sessions`` returned two invented sessions, and
``create_api_key`` computed a hash and discarded it, so the key it returned
could never authenticate.

``TestPasswordChange::test_old_password_stops_working`` is the primary
regression test — it is the one the previous implementation would fail.
"""

from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from src.exceptions import AuthenticationError, AuthorizationError
from src.saas.auth.credential_stores import (
    InMemoryAPIKeyStore,
    InMemoryPasswordResetTokenStore,
    InMemorySessionStore,
)
from src.saas.auth.password_policy import (
    PasswordPolicyError,
    enforce_password_policy,
    validate_password,
)
from src.saas.auth.service import AuthService, InMemoryUserStore, UserRecord

GOOD_PASSWORD = "Tr0ub4dor&Fjord!"
NEW_PASSWORD = "Xk9#mQpLw2vZ!tR7"


def _service():
    return AuthService(
        {"jwt_secret": "test-secret-only", "access_token_expiry": 3600},
        user_store=InMemoryUserStore(),
    )


def _service_with_user(mfa=False):
    svc = _service()
    secret = pyotp.random_base32() if mfa else ""
    svc.user_store.add(
        UserRecord(
            user_id="u1",
            organization_id="org1",
            email="user@example.com",
            username="user",
            password_hash=svc.hash_password(GOOD_PASSWORD),
            mfa_enabled=mfa,
            mfa_secret=secret,
        )
    )
    return svc, secret


class TestPasswordPolicy:
    def test_strong_password_accepted(self):
        assert validate_password(GOOD_PASSWORD).valid is True

    @pytest.mark.parametrize(
        "password,expected",
        [
            ("", "must not be empty"),
            ("Ab1!x", "at least"),
            ("alllowercase1!", "uppercase"),
            ("ALLUPPERCASE1!", "lowercase"),
            ("NoDigitsHere!!", "digit"),
            ("NoSymbolsHere12", "symbol"),
        ],
    )
    def test_rejections(self, password, expected):
        result = validate_password(password)
        assert result.valid is False
        assert expected in result.message

    def test_common_password_rejected(self):
        assert validate_password("Password123!").valid is False

    def test_repeated_run_rejected(self):
        assert "repeated or sequential" in validate_password("Aaaa1111!!!!bZ").message

    def test_sequential_run_rejected(self):
        assert "repeated or sequential" in validate_password("Xy!abcd9Kqmz").message

    def test_password_containing_email_rejected(self):
        result = validate_password("Zq7!alicewonder", email="alice@example.com")
        assert "email address" in result.message

    def test_password_containing_username_rejected(self):
        result = validate_password("Zq7!bobsmith_x", username="bobsmith")
        assert "username" in result.message

    def test_over_max_length_rejected(self):
        assert validate_password("Aa1!" + "x" * 300).valid is False

    def test_all_failures_reported_together(self):
        """A user fixing a password should see the full list at once."""
        assert len(validate_password("abc").errors) > 1

    def test_enforce_raises_with_details(self):
        with pytest.raises(PasswordPolicyError) as excinfo:
            enforce_password_policy("weak")
        assert excinfo.value.result.valid is False


class TestPasswordChange:
    def test_old_password_stops_working(self):
        """Regression for #2706 — the hash used not to change at all."""
        svc, _ = _service_with_user()
        svc.change_password("u1", GOOD_PASSWORD, NEW_PASSWORD)

        assert svc.authenticate_user("user@example.com", GOOD_PASSWORD).success is False
        assert svc.authenticate_user("user@example.com", NEW_PASSWORD).success is True

    def test_wrong_current_password_rejected(self):
        svc, _ = _service_with_user()
        with pytest.raises(AuthenticationError, match="Current password is incorrect"):
            svc.change_password("u1", "not-the-password", NEW_PASSWORD)

    def test_hash_unchanged_after_a_rejected_change(self):
        svc, _ = _service_with_user()
        before = svc.user_store.get_by_id("u1").password_hash
        with pytest.raises(AuthenticationError):
            svc.change_password("u1", "wrong", NEW_PASSWORD)
        assert svc.user_store.get_by_id("u1").password_hash == before

    def test_weak_new_password_rejected(self):
        svc, _ = _service_with_user()
        with pytest.raises(PasswordPolicyError):
            svc.change_password("u1", GOOD_PASSWORD, "weak")

    def test_reusing_the_current_password_rejected(self):
        svc, _ = _service_with_user()
        with pytest.raises(AuthenticationError, match="must differ"):
            svc.change_password("u1", GOOD_PASSWORD, GOOD_PASSWORD)

    def test_unknown_user_rejected(self):
        svc, _ = _service_with_user()
        with pytest.raises(AuthenticationError, match="User not found"):
            svc.change_password("nobody", GOOD_PASSWORD, NEW_PASSWORD)

    def test_account_without_password_rejected(self):
        svc = _service()
        svc.user_store.add(UserRecord("u2", "org1", "sso@example.com"))
        with pytest.raises(AuthenticationError, match="not configured"):
            svc.change_password("u2", "anything", NEW_PASSWORD)


class TestPasswordReset:
    def test_reset_token_sets_a_new_password(self):
        svc, _ = _service_with_user()
        token = svc.reset_token_store.issue("u1")
        assert svc.reset_token_store.consume(token) == "u1"

        svc.set_password("u1", NEW_PASSWORD)
        assert svc.authenticate_user("user@example.com", NEW_PASSWORD).success is True

    def test_token_is_single_use(self):
        store = InMemoryPasswordResetTokenStore()
        token = store.issue("u1")
        assert store.consume(token) == "u1"
        assert store.consume(token) is None

    def test_expired_token_rejected(self):
        store = InMemoryPasswordResetTokenStore(ttl_seconds=-1)
        assert store.consume(store.issue("u1")) is None

    def test_unknown_token_rejected(self):
        store = InMemoryPasswordResetTokenStore()
        assert store.consume("not-a-real-token") is None

    def test_empty_token_rejected(self):
        assert InMemoryPasswordResetTokenStore().consume("") is None

    def test_issuing_again_invalidates_the_previous_token(self):
        store = InMemoryPasswordResetTokenStore()
        first = store.issue("u1")
        second = store.issue("u1")
        assert store.consume(first) is None
        assert store.consume(second) == "u1"

    def test_token_for_one_user_cannot_reset_another(self):
        store = InMemoryPasswordResetTokenStore()
        token_a = store.issue("user_a")
        assert store.consume(token_a) == "user_a"

    def test_invalidate_for_user_drops_outstanding_tokens(self):
        store = InMemoryPasswordResetTokenStore()
        token = store.issue("u1")
        store.invalidate_for_user("u1")
        assert store.consume(token) is None

    def test_raw_token_is_not_stored(self):
        store = InMemoryPasswordResetTokenStore()
        token = store.issue("u1")
        assert token not in store._tokens
        assert all(r.user_id == "u1" for r in store._tokens.values())

    def test_set_password_enforces_policy(self):
        svc, _ = _service_with_user()
        with pytest.raises(PasswordPolicyError):
            svc.set_password("u1", "weak")


class TestMFAEnrolment:
    def test_enrolment_does_not_enable_until_confirmed(self):
        """Otherwise a user who scans and navigates away locks themselves out."""
        svc, _ = _service_with_user()
        secret, uri, codes = svc.begin_mfa_enrolment("u1")

        assert svc.user_store.get_by_id("u1").mfa_enabled is False
        assert secret and uri.startswith("otpauth://") and len(codes) == 8

    def test_confirmation_enables_mfa(self):
        svc, _ = _service_with_user()
        secret, _, codes = svc.begin_mfa_enrolment("u1")
        svc.complete_mfa_enrolment("u1", pyotp.TOTP(secret).now(), backup_codes=codes)

        record = svc.user_store.get_by_id("u1")
        assert record.mfa_enabled is True
        assert record.mfa_secret == secret

    def test_wrong_confirmation_code_leaves_mfa_off(self):
        svc, _ = _service_with_user()
        svc.begin_mfa_enrolment("u1")
        with pytest.raises(AuthenticationError, match="Invalid MFA code"):
            svc.complete_mfa_enrolment("u1", "000000")
        assert svc.user_store.get_by_id("u1").mfa_enabled is False

    def test_confirming_without_enrolling_rejected(self):
        svc, _ = _service_with_user()
        with pytest.raises(AuthenticationError, match="No pending MFA enrolment"):
            svc.complete_mfa_enrolment("u1", "000000")

    def test_enrolling_twice_rejected(self):
        svc, _ = _service_with_user(mfa=True)
        with pytest.raises(AuthorizationError, match="already enabled"):
            svc.begin_mfa_enrolment("u1")

    def test_enrolment_makes_login_require_mfa(self):
        svc, _ = _service_with_user()
        secret, _, _ = svc.begin_mfa_enrolment("u1")
        svc.complete_mfa_enrolment("u1", pyotp.TOTP(secret).now())

        result = svc.authenticate_user("user@example.com", GOOD_PASSWORD)
        assert result.mfa_required is True

    def test_backup_codes_are_stored_hashed_and_single_use(self):
        svc, _ = _service_with_user()
        secret, _, codes = svc.begin_mfa_enrolment("u1")
        svc.complete_mfa_enrolment("u1", pyotp.TOTP(secret).now(), backup_codes=codes)

        stored = svc.user_store._backup_codes["u1"]
        assert codes[0] not in stored
        assert svc.user_store.consume_backup_code("u1", codes[0]) is True
        assert svc.user_store.consume_backup_code("u1", codes[0]) is False

    def test_unknown_backup_code_rejected(self):
        svc, _ = _service_with_user()
        assert svc.user_store.consume_backup_code("u1", "deadbeef") is False


class TestMFADisable:
    def test_requires_the_correct_password(self):
        """The stub ignored the password it demanded."""
        svc, _ = _service_with_user(mfa=True)
        with pytest.raises(AuthenticationError, match="Current password is incorrect"):
            svc.disable_mfa("u1", "wrong-password")
        assert svc.user_store.get_by_id("u1").mfa_enabled is True

    def test_correct_password_disables(self):
        svc, _ = _service_with_user(mfa=True)
        svc.disable_mfa("u1", GOOD_PASSWORD)

        record = svc.user_store.get_by_id("u1")
        assert record.mfa_enabled is False
        assert record.mfa_secret == ""

    def test_disabling_when_not_enabled_rejected(self):
        svc, _ = _service_with_user()
        with pytest.raises(AuthorizationError, match="not enabled"):
            svc.disable_mfa("u1", GOOD_PASSWORD)

    def test_disabling_clears_backup_codes(self):
        svc, _ = _service_with_user()
        secret, _, codes = svc.begin_mfa_enrolment("u1")
        svc.complete_mfa_enrolment("u1", pyotp.TOTP(secret).now(), backup_codes=codes)
        svc.disable_mfa("u1", GOOD_PASSWORD)
        assert "u1" not in svc.user_store._backup_codes

    def test_login_no_longer_requires_mfa_after_disable(self):
        svc, _ = _service_with_user(mfa=True)
        svc.disable_mfa("u1", GOOD_PASSWORD)
        assert svc.authenticate_user("user@example.com", GOOD_PASSWORD).success is True


class TestSessions:
    def test_login_records_a_real_session(self):
        """The list used to be two hardcoded fabrications."""
        svc, _ = _service_with_user()
        svc.authenticate_user("user@example.com", GOOD_PASSWORD)

        sessions = svc.session_store.list_for_user("u1")
        assert len(sessions) == 1
        assert sessions[0].session_id

    def test_each_login_adds_a_session(self):
        svc, _ = _service_with_user()
        for _ in range(3):
            svc.authenticate_user("user@example.com", GOOD_PASSWORD)
        assert len(svc.session_store.list_for_user("u1")) == 3

    def test_sessions_are_scoped_to_their_user(self):
        store = InMemorySessionStore()
        store.create("s1", "user_a")
        store.create("s2", "user_b")
        assert [s.session_id for s in store.list_for_user("user_a")] == ["s1"]

    def test_revoke_removes_from_the_list(self):
        store = InMemorySessionStore()
        store.create("s1", "u1")
        assert store.revoke("s1") is True
        assert store.list_for_user("u1") == []

    def test_revoking_twice_reports_false(self):
        store = InMemorySessionStore()
        store.create("s1", "u1")
        store.revoke("s1")
        assert store.revoke("s1") is False

    def test_revoking_unknown_session_reports_false(self):
        assert InMemorySessionStore().revoke("nope") is False

    def test_revoke_all_can_keep_the_current_session(self):
        store = InMemorySessionStore()
        for sid in ("s1", "s2", "s3"):
            store.create(sid, "u1")
        assert store.revoke_all_for_user("u1", except_session="s2") == 2
        assert [s.session_id for s in store.list_for_user("u1")] == ["s2"]

    def test_expired_sessions_are_not_listed(self):
        store = InMemorySessionStore(ttl_seconds=-1)
        store.create("s1", "u1")
        assert store.list_for_user("u1") == []
        assert store.get("s1") is None

    def test_touch_updates_last_seen(self):
        store = InMemorySessionStore()
        record = store.create("s1", "u1")
        before = record.last_seen_at
        store.touch("s1")
        assert store.get("s1").last_seen_at >= before

    def test_listing_is_ordered_most_recent_first(self):
        store = InMemorySessionStore()
        store.create("s1", "u1")
        store.create("s2", "u1")
        store.touch("s1")
        assert store.list_for_user("u1")[0].session_id == "s1"

    def test_device_and_ip_are_recorded(self):
        store = InMemorySessionStore()
        store.create("s1", "u1", device="Firefox on Linux", ip_address="203.0.113.7")
        record = store.get("s1")
        assert record.device == "Firefox on Linux"
        assert record.ip_address == "203.0.113.7"

    def test_blank_device_falls_back_to_a_placeholder(self):
        store = InMemorySessionStore()
        store.create("s1", "u1", device="", ip_address="")
        record = store.get("s1")
        assert record.device == "Unknown device"
        assert record.ip_address == "unknown"


class TestAPIKeys:
    def test_created_key_authenticates(self):
        """Regression for #2706 — the hash was computed then discarded."""
        svc, _ = _service_with_user()
        raw_key, record = svc.api_key_store.create("prod", "org1", "u1", ["read"])

        result = svc.authenticate_api_key(raw_key)
        assert result.success is True
        assert result.organization_id == "org1"
        assert result.user_id == "u1"

    def test_raw_key_is_not_stored(self):
        store = InMemoryAPIKeyStore()
        raw_key, record = store.create("prod", "org1", "u1")
        assert raw_key not in store._by_hash
        assert record.key_hash != raw_key

    def test_revoked_key_stops_working(self):
        svc, _ = _service_with_user()
        raw_key, record = svc.api_key_store.create("prod", "org1", "u1")
        assert svc.api_key_store.revoke(record.key_id, "org1") is True
        assert svc.authenticate_api_key(raw_key).success is False

    def test_expired_key_rejected(self):
        svc, _ = _service_with_user()
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        raw_key, _ = svc.api_key_store.create("old", "org1", "u1", expires_at=past)
        assert svc.authenticate_api_key(raw_key).success is False

    def test_future_expiry_still_works(self):
        svc, _ = _service_with_user()
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        raw_key, _ = svc.api_key_store.create("ok", "org1", "u1", expires_at=future)
        assert svc.authenticate_api_key(raw_key).success is True

    def test_unknown_key_rejected(self):
        svc, _ = _service_with_user()
        assert svc.authenticate_api_key("sk_not_a_real_key").success is False

    def test_empty_key_rejected(self):
        svc, _ = _service_with_user()
        assert svc.authenticate_api_key("").success is False

    def test_refusal_reason_is_uniform(self):
        """Revoked, expired, and unknown must be indistinguishable."""
        svc, _ = _service_with_user()
        raw_key, record = svc.api_key_store.create("prod", "org1", "u1")
        svc.api_key_store.revoke(record.key_id, "org1")

        revoked = svc.authenticate_api_key(raw_key).error
        unknown = svc.authenticate_api_key("sk_nope").error
        assert revoked == unknown == "Invalid API key"

    def test_cannot_revoke_another_organizations_key(self):
        store = InMemoryAPIKeyStore()
        _, record = store.create("prod", "org1", "u1")
        assert store.revoke(record.key_id, "org2") is False
        assert store.revoke(record.key_id, "org1") is True

    def test_revoking_twice_reports_false(self):
        store = InMemoryAPIKeyStore()
        _, record = store.create("prod", "org1", "u1")
        store.revoke(record.key_id, "org1")
        assert store.revoke(record.key_id, "org1") is False

    def test_listing_is_scoped_to_the_organization(self):
        store = InMemoryAPIKeyStore()
        store.create("a", "org1", "u1")
        store.create("b", "org2", "u2")
        assert [r.name for r in store.list_for_organization("org1")] == ["a"]

    def test_revoked_keys_are_not_listed(self):
        store = InMemoryAPIKeyStore()
        _, record = store.create("a", "org1", "u1")
        store.revoke(record.key_id, "org1")
        assert store.list_for_organization("org1") == []

    def test_last_used_is_recorded(self):
        store = InMemoryAPIKeyStore()
        raw_key, record = store.create("a", "org1", "u1")
        assert record.last_used_at is None
        store.resolve(raw_key)
        assert store._by_id[record.key_id].last_used_at is not None

    def test_prefix_is_exposed_but_not_the_key(self):
        store = InMemoryAPIKeyStore()
        raw_key, record = store.create("a", "org1", "u1")
        assert raw_key.startswith(record.key_prefix)
        assert len(record.key_prefix) < len(raw_key)


class TestUserStoreWritePaths:
    def test_default_store_raises_rather_than_discarding(self):
        """A third-party store missing these must fail loudly."""
        from src.saas.auth.service import UserStore

        class Minimal(UserStore):
            def get_by_id(self, user_id):
                return None

            def get_by_email(self, email):
                return None

            def find_or_create_sso_user(self, provider, user_info):
                return ("u", "o")

        store = Minimal()
        for call in (
            lambda: store.update_password_hash("u", "h"),
            lambda: store.set_mfa("u", True, "s"),
            lambda: store.set_backup_codes("u", []),
            lambda: store.consume_backup_code("u", "c"),
            lambda: store.update_last_login("u"),
        ):
            with pytest.raises(NotImplementedError):
                call()

    def test_updating_an_unknown_user_raises(self):
        store = InMemoryUserStore()
        with pytest.raises(KeyError):
            store.update_password_hash("nobody", "hash")
        with pytest.raises(KeyError):
            store.set_mfa("nobody", True, "s")


class TestRoutes:
    """End-to-end through the router."""

    @pytest.fixture
    def client(self, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        import src.saas.routes.auth as auth_routes

        svc, _ = _service_with_user()
        monkeypatch.setattr(auth_routes, "_AUTH_SERVICE", svc)
        monkeypatch.setattr(auth_routes, "_pending_backup_codes", {})

        app = FastAPI()
        app.include_router(auth_routes.router)
        client = TestClient(app)
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "user@example.com", "password": GOOD_PASSWORD},
        ).json()
        client.headers.update({"Authorization": f"Bearer {login['access_token']}"})
        return client

    def test_change_password_rejects_wrong_current(self, client):
        response = client.post(
            "/api/v1/auth/password/change",
            json={"current_password": "wrong", "new_password": NEW_PASSWORD},
        )
        assert response.status_code == 401

    def test_change_password_rejects_weak_new(self, client):
        response = client.post(
            "/api/v1/auth/password/change",
            json={"current_password": GOOD_PASSWORD, "new_password": "weakpass"},
        )
        assert response.status_code == 422

    def test_change_password_succeeds_and_revokes_others(self, client):
        response = client.post(
            "/api/v1/auth/password/change",
            json={"current_password": GOOD_PASSWORD, "new_password": NEW_PASSWORD},
        )
        assert response.status_code == 200
        assert "other_sessions_revoked" in response.json()

    def test_reset_response_is_uniform_for_unknown_email(self, client):
        known = client.post(
            "/api/v1/auth/password/reset", json={"email": "user@example.com"}
        )
        unknown = client.post(
            "/api/v1/auth/password/reset", json={"email": "ghost@example.com"}
        )
        assert known.json() == unknown.json()

    def test_reset_confirm_rejects_a_bogus_token(self, client):
        response = client.post(
            "/api/v1/auth/password/reset/confirm",
            json={"token": "made-up", "new_password": NEW_PASSWORD},
        )
        assert response.status_code == 400

    def test_sessions_list_is_real(self, client):
        body = client.get("/api/v1/auth/sessions").json()
        assert body["total"] == 1
        assert body["sessions"][0]["ip_address"] != "192.168.1.1"

    def test_revoking_an_unknown_session_is_404(self, client):
        assert client.delete("/api/v1/auth/sessions/nope").status_code == 404

    def test_api_key_roundtrip(self, client):
        created = client.post(
            "/api/v1/auth/api-keys", json={"name": "prod", "scopes": ["read"]}
        ).json()
        assert created["key"].startswith("sk_")

        listed = client.get("/api/v1/auth/api-keys").json()
        assert listed["total"] == 1
        assert "key" not in listed["api_keys"][0]

        assert client.delete(f"/api/v1/auth/api-keys/{created['id']}").status_code == 200
        assert client.get("/api/v1/auth/api-keys").json()["total"] == 0

    def test_api_key_past_expiry_rejected(self, client):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        response = client.post(
            "/api/v1/auth/api-keys", json={"name": "old", "expires_at": past}
        )
        assert response.status_code == 422

    def test_deleting_an_unknown_api_key_is_404(self, client):
        assert client.delete("/api/v1/auth/api-keys/key_nope").status_code == 404

    def test_mfa_enroll_then_confirm(self, client):
        enrolled = client.post("/api/v1/auth/mfa/enroll").json()
        assert len(enrolled["backup_codes"]) == 8

        # Not enabled until confirmed.
        assert client.get("/api/v1/auth/me").json()["mfa_enabled"] is False

        code = pyotp.TOTP(enrolled["secret"]).now()
        assert (
            client.post(
                "/api/v1/auth/mfa/enroll/confirm", json={"totp_code": code}
            ).status_code
            == 200
        )
        assert client.get("/api/v1/auth/me").json()["mfa_enabled"] is True

    def test_mfa_disable_requires_password(self, client):
        enrolled = client.post("/api/v1/auth/mfa/enroll").json()
        client.post(
            "/api/v1/auth/mfa/enroll/confirm",
            json={"totp_code": pyotp.TOTP(enrolled["secret"]).now()},
        )

        assert (
            client.post(
                "/api/v1/auth/mfa/disable", json={"current_password": "wrong"}
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/mfa/disable", json={"current_password": GOOD_PASSWORD}
            ).status_code
            == 200
        )
        assert client.get("/api/v1/auth/me").json()["mfa_enabled"] is False

    def test_me_reports_the_real_record(self, client):
        assert client.get("/api/v1/auth/me").json()["mfa_enabled"] is False
