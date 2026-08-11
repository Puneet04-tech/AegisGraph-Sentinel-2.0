"""Tests for session revocation and refresh-token rotation.

Covers the vulnerability fixed in issue #2702: ``logout()`` revoked only the
access token's ``jti``, while ``refresh_tokens()`` never consulted the
revocation set at all. A refresh token captured before logout therefore kept
minting access tokens for the remainder of its 7-day lifetime.

The regression test that matters most is
``TestLogoutEndsSession::test_refresh_after_logout_is_rejected`` — it reproduces
the original attack directly.
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.exceptions import AuthenticationError
from src.saas.auth.revocation import (
    InMemoryTokenRevocationStore,
    RedisTokenRevocationStore,
    TokenRevocationStore,
    build_revocation_store,
)
from src.saas.auth.service import AuthService, InMemoryUserStore, UserRecord


def _make_service(users=None, revocation_store=None):
    store = InMemoryUserStore()
    for u in (users or []):
        store.add(u)
    return AuthService(
        {"jwt_secret": "test-secret-only", "access_token_expiry": 3600},
        user_store=store,
        revocation_store=revocation_store,
    )


def _logged_in_user(email="user@example.com", user_id="u_rev", revocation_store=None):
    """Return (service, auth_result) for a freshly authenticated user."""
    svc = _make_service(revocation_store=revocation_store)
    record = UserRecord(
        user_id=user_id,
        organization_id="org_rev",
        email=email,
        password_hash=svc.hash_password("correct-password"),
    )
    svc.user_store.add(record)
    result = svc.authenticate_user(email, "correct-password")
    assert result.success is True
    return svc, result


class TestLogoutEndsSession:
    """The original vulnerability and its fix."""

    def test_refresh_after_logout_is_rejected(self):
        """Regression for #2702 — the exact attack from the issue.

        Before the fix this call succeeded and returned a fresh token pair,
        restoring full access after the user had explicitly signed out.
        """
        svc, login = _logged_in_user()
        payload = svc.verify_token(login.access_token)

        svc.revoke_session(payload.sid)

        with pytest.raises(AuthenticationError, match="Session has been revoked"):
            svc.refresh_tokens(login.refresh_token)

    def test_access_token_rejected_after_session_revoked(self):
        svc, login = _logged_in_user()
        payload = svc.verify_token(login.access_token)

        svc.revoke_session(payload.sid)

        with pytest.raises(AuthenticationError, match="Session has been revoked"):
            svc.verify_token(login.access_token)

    def test_access_token_valid_before_revocation(self):
        svc, login = _logged_in_user()
        assert svc.verify_token(login.access_token).sub == "u_rev"

    def test_revoking_one_session_leaves_another_alive(self):
        """Signing out on one device must not sign the user out everywhere."""
        svc, first = _logged_in_user()
        second = svc.authenticate_user("user@example.com", "correct-password")
        assert second.success is True

        first_payload = svc.verify_token(first.access_token)
        svc.revoke_session(first_payload.sid)

        with pytest.raises(AuthenticationError):
            svc.verify_token(first.access_token)
        assert svc.verify_token(second.access_token).sub == "u_rev"
        assert svc.refresh_tokens(second.refresh_token).success is True

    def test_access_and_refresh_share_a_session_id(self):
        import jwt

        svc, login = _logged_in_user()
        access = svc.verify_token(login.access_token)
        refresh = jwt.decode(
            login.refresh_token, svc.jwt_secret, algorithms=[svc.jwt_algorithm]
        )
        assert access.sid
        assert access.sid == refresh["session"]


class TestRefreshRotation:
    def test_refresh_succeeds_once(self):
        svc, login = _logged_in_user()
        rotated = svc.refresh_tokens(login.refresh_token)
        assert rotated.success is True
        assert rotated.access_token != login.access_token
        assert rotated.refresh_token != login.refresh_token

    def test_old_refresh_token_rejected_after_rotation(self):
        svc, login = _logged_in_user()
        svc.refresh_tokens(login.refresh_token)

        with pytest.raises(AuthenticationError, match="already been used"):
            svc.refresh_tokens(login.refresh_token)

    def test_replay_revokes_the_whole_session(self):
        """A replayed refresh token means two parties hold it — burn the family."""
        svc, login = _logged_in_user()
        rotated = svc.refresh_tokens(login.refresh_token)

        with pytest.raises(AuthenticationError):
            svc.refresh_tokens(login.refresh_token)

        # The rotated token was legitimate, but the session is now untrusted.
        with pytest.raises(AuthenticationError, match="Session has been revoked"):
            svc.refresh_tokens(rotated.refresh_token)
        with pytest.raises(AuthenticationError, match="Session has been revoked"):
            svc.verify_token(rotated.access_token)

    def test_rotated_token_can_itself_be_rotated(self):
        svc, login = _logged_in_user()
        first = svc.refresh_tokens(login.refresh_token)
        second = svc.refresh_tokens(first.refresh_token)
        assert second.success is True

    def test_deleted_user_revokes_session(self):
        svc, login = _logged_in_user()
        svc.user_store._users.clear()

        with pytest.raises(AuthenticationError, match="User not found"):
            svc.refresh_tokens(login.refresh_token)

        with pytest.raises(AuthenticationError, match="Session has been revoked"):
            svc.verify_token(login.access_token)


class TestRefreshTokenValidation:
    def test_access_token_rejected_on_refresh_path(self):
        svc, login = _logged_in_user()
        with pytest.raises(AuthenticationError, match="not a refresh token"):
            svc.refresh_tokens(login.access_token)

    def test_garbage_token_rejected(self):
        svc, _ = _logged_in_user()
        with pytest.raises(AuthenticationError, match="Invalid refresh token"):
            svc.refresh_tokens("not-a-jwt")

    def test_expired_refresh_token_rejected(self):
        import jwt

        svc, _ = _logged_in_user()
        now = datetime.now(timezone.utc)
        expired = jwt.encode(
            {
                "sub": "u_rev",
                "session": "s1",
                "type": "refresh",
                "exp": now - timedelta(seconds=10),
                "iat": now - timedelta(seconds=20),
                "jti": "j1",
            },
            svc.jwt_secret,
            algorithm=svc.jwt_algorithm,
        )
        with pytest.raises(AuthenticationError, match="expired"):
            svc.refresh_tokens(expired)

    def test_refresh_token_without_session_rejected(self):
        """A legacy token predating session stamping cannot be rotated safely."""
        import jwt

        svc, _ = _logged_in_user()
        now = datetime.now(timezone.utc)
        legacy = jwt.encode(
            {
                "sub": "u_rev",
                "type": "refresh",
                "exp": now + timedelta(hours=1),
                "iat": now,
                "jti": "legacy-jti",
            },
            svc.jwt_secret,
            algorithm=svc.jwt_algorithm,
        )
        with pytest.raises(AuthenticationError, match="missing session"):
            svc.refresh_tokens(legacy)

    def test_token_signed_with_another_secret_rejected(self):
        import jwt

        svc, _ = _logged_in_user()
        now = datetime.now(timezone.utc)
        forged = jwt.encode(
            {
                "sub": "u_rev",
                "session": "s1",
                "type": "refresh",
                "exp": now + timedelta(hours=1),
                "iat": now,
                "jti": "forged",
            },
            "a-different-secret",
            algorithm="HS256",
        )
        with pytest.raises(AuthenticationError, match="Invalid refresh token"):
            svc.refresh_tokens(forged)

    def test_access_token_missing_claim_is_invalid_not_a_crash(self):
        import jwt

        svc, _ = _logged_in_user()
        now = datetime.now(timezone.utc)
        incomplete = jwt.encode(
            {"sub": "u_rev", "exp": now + timedelta(hours=1), "iat": now, "jti": "x"},
            svc.jwt_secret,
            algorithm=svc.jwt_algorithm,
        )
        with pytest.raises(AuthenticationError, match="Malformed token"):
            svc.verify_token(incomplete)


class TestInMemoryRevocationStore:
    def test_revoked_token_reported(self):
        store = InMemoryTokenRevocationStore()
        store.revoke_token("jti-1")
        assert store.is_token_revoked("jti-1") is True
        assert store.is_token_revoked("jti-2") is False

    def test_revoked_session_reported(self):
        store = InMemoryTokenRevocationStore()
        store.revoke_session("sess-1")
        assert store.is_session_revoked("sess-1") is True
        assert store.is_session_revoked("sess-2") is False

    def test_empty_identifiers_are_not_revoked(self):
        store = InMemoryTokenRevocationStore()
        store.revoke_token("")
        store.revoke_session("")
        assert store.is_token_revoked("") is False
        assert store.is_session_revoked("") is False
        assert store.consume_refresh_jti("", "sess") is False

    def test_expired_entries_are_purged(self):
        store = InMemoryTokenRevocationStore()
        past = datetime.now(timezone.utc) - timedelta(days=1)
        store.revoke_token("old-jti", expires_at=past)
        # The floor keeps a short tombstone alive, so force expiry directly to
        # assert the sweep itself rather than waiting out the floor.
        store._tokens["old-jti"] = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert store.is_token_revoked("old-jti") is False
        assert "old-jti" not in store._tokens

    def test_short_lived_tokens_keep_a_minimum_tombstone(self):
        """Clock skew between workers must not open a replay window."""
        store = InMemoryTokenRevocationStore()
        store.revoke_token("just-expired", expires_at=datetime.now(timezone.utc))
        assert store.is_token_revoked("just-expired") is True

    def test_naive_datetime_is_treated_as_utc(self):
        store = InMemoryTokenRevocationStore()
        naive = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
        store.revoke_token("naive", expires_at=naive)
        assert store.is_token_revoked("naive") is True

    def test_consume_is_single_use(self):
        store = InMemoryTokenRevocationStore()
        assert store.consume_refresh_jti("j", "sess") is True
        assert store.consume_refresh_jti("j", "sess") is False

    def test_consume_replay_revokes_session(self):
        store = InMemoryTokenRevocationStore()
        store.consume_refresh_jti("j", "sess")
        store.consume_refresh_jti("j", "sess")
        assert store.is_session_revoked("sess") is True

    def test_clear_resets_state(self):
        store = InMemoryTokenRevocationStore()
        store.revoke_token("a")
        store.revoke_session("b")
        store.consume_refresh_jti("c", "d")
        store.clear()
        assert store.is_token_revoked("a") is False
        assert store.is_session_revoked("b") is False
        assert store.consume_refresh_jti("c", "d") is True

    def test_reports_itself_as_process_local(self):
        assert InMemoryTokenRevocationStore().is_shared is False

    def test_concurrent_consume_admits_exactly_one_winner(self):
        """Two parallel refreshes of the same token: only one may succeed."""
        import threading

        store = InMemoryTokenRevocationStore()
        results = []
        barrier = threading.Barrier(8)

        def attempt():
            barrier.wait()
            results.append(store.consume_refresh_jti("contended", "sess"))

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results.count(True) == 1
        assert store.is_session_revoked("sess") is True


class _BrokenRedis:
    """Stands in for a Redis instance that is down."""

    def setex(self, *args, **kwargs):
        raise ConnectionError("redis is down")

    def exists(self, *args, **kwargs):
        raise ConnectionError("redis is down")

    def set(self, *args, **kwargs):
        raise ConnectionError("redis is down")


class TestRedisRevocationStoreFailsClosed:
    """Unlike the rate limiter, revocation must not fail open."""

    @pytest.fixture
    def broken_store(self, monkeypatch):
        store = RedisTokenRevocationStore()
        monkeypatch.setattr(store, "_client", lambda: _BrokenRedis())
        return store

    def test_token_check_fails_closed(self, broken_store):
        assert broken_store.is_token_revoked("any-jti") is True

    def test_session_check_fails_closed(self, broken_store):
        assert broken_store.is_session_revoked("any-session") is True

    def test_consume_fails_closed(self, broken_store):
        assert broken_store.consume_refresh_jti("j", "sess") is False

    def test_failed_revocation_raises_rather_than_silently_dropping(self, broken_store):
        with pytest.raises(ConnectionError):
            broken_store.revoke_token("jti")
        with pytest.raises(ConnectionError):
            broken_store.revoke_session("sess")

    def test_reports_itself_as_shared(self):
        assert RedisTokenRevocationStore().is_shared is True


class TestSharedStoreAcrossWorkers:
    def test_two_services_sharing_a_store_see_the_same_revocation(self):
        """Models two uvicorn workers backed by one Redis instance."""
        shared = InMemoryTokenRevocationStore()
        worker_a, login = _logged_in_user(revocation_store=shared)

        worker_b = _make_service(revocation_store=shared)
        worker_b.jwt_secret = worker_a.jwt_secret
        worker_b.user_store = worker_a.user_store

        payload = worker_a.verify_token(login.access_token)
        worker_a.revoke_session(payload.sid)

        # Logout landed on worker A; the attacker's next request hits worker B.
        with pytest.raises(AuthenticationError, match="Session has been revoked"):
            worker_b.refresh_tokens(login.refresh_token)
        with pytest.raises(AuthenticationError, match="Session has been revoked"):
            worker_b.verify_token(login.access_token)

    def test_separate_stores_do_not_share_state(self):
        """Documents why the in-memory backend is unsafe for multiple workers."""
        worker_a, login = _logged_in_user()
        worker_b = _make_service()
        worker_b.jwt_secret = worker_a.jwt_secret
        worker_b.user_store = worker_a.user_store

        payload = worker_a.verify_token(login.access_token)
        worker_a.revoke_session(payload.sid)

        assert worker_b.verify_token(login.access_token).sub == "u_rev"


class TestBuildRevocationStore:
    def test_memory_backend(self):
        assert isinstance(build_revocation_store("memory"), InMemoryTokenRevocationStore)

    def test_redis_backend(self):
        assert isinstance(
            build_revocation_store("redis", "redis://localhost:6379/0"),
            RedisTokenRevocationStore,
        )

    def test_backend_name_is_case_and_space_insensitive(self):
        assert isinstance(build_revocation_store("  REDIS "), RedisTokenRevocationStore)

    def test_unknown_backend_falls_back_to_memory(self, caplog):
        store = build_revocation_store("postgres")
        assert isinstance(store, InMemoryTokenRevocationStore)
        assert "Unknown revocation backend" in caplog.text

    def test_none_backend_defaults_to_memory(self):
        assert isinstance(build_revocation_store(None), InMemoryTokenRevocationStore)


class TestBackwardCompatibleView:
    """The old ``revoked_token_ids`` set API must keep working."""

    def test_membership_test(self):
        svc, login = _logged_in_user()
        payload = svc.verify_token(login.access_token)
        assert payload.jti not in svc.revoked_token_ids
        svc.revoke_token_id(payload.jti)
        assert payload.jti in svc.revoked_token_ids

    def test_add_revokes(self):
        svc, login = _logged_in_user()
        payload = svc.verify_token(login.access_token)
        svc.revoked_token_ids.add(payload.jti)
        with pytest.raises(AuthenticationError, match="Token has been revoked"):
            svc.verify_token(login.access_token)

    def test_non_string_membership_is_false(self):
        svc, _ = _logged_in_user()
        assert 42 not in svc.revoked_token_ids

    def test_discard_is_refused(self):
        svc, _ = _logged_in_user()
        with pytest.raises(NotImplementedError):
            svc.revoked_token_ids.discard("anything")


class TestDefaultsAndWarnings:
    def test_default_store_is_in_memory(self):
        assert isinstance(
            _make_service().revocation_store, InMemoryTokenRevocationStore
        )

    def test_in_memory_default_warns_about_multi_worker(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING, logger="src.saas.auth.service"):
            _make_service()
        assert "process-local" in caplog.text

    def test_injected_shared_store_does_not_warn(self, caplog):
        import logging

        class _Shared(InMemoryTokenRevocationStore):
            @property
            def is_shared(self) -> bool:
                return True

        with caplog.at_level(logging.WARNING, logger="src.saas.auth.service"):
            _make_service(revocation_store=_Shared())
        assert "process-local" not in caplog.text

    def test_store_satisfies_the_interface(self):
        for store in (InMemoryTokenRevocationStore(), RedisTokenRevocationStore()):
            assert isinstance(store, TokenRevocationStore)
