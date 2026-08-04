"""Tests for authentication lockout and brute-force protection.

Covers the vulnerability fixed in issue #2703: ``authenticate_user()`` and
``verify_mfa()`` answered every request with no attempt counter, no lockout,
and no per-account throttle, so passwords could be sprayed and 6-digit TOTP
codes brute-forced at line rate.

``TestLoginLockout::test_account_locks_after_threshold_failures`` is the
primary regression test.
"""

import threading

import pyotp
import pytest

from src.saas.auth.attempt_limiter import (
    SCOPE_ACCOUNT,
    SCOPE_ADDRESS,
    SCOPE_TOTP,
    AuthAttemptLimiter,
    InMemoryAttemptLimiter,
    LockoutState,
    RedisAttemptLimiter,
    build_attempt_limiter,
)
from src.saas.auth.service import AuthService, InMemoryUserStore, UserRecord

PASSWORD = "correct-horse-battery"


def _make_service(users=None, limiter=None):
    store = InMemoryUserStore()
    for u in (users or []):
        store.add(u)
    return AuthService(
        {"jwt_secret": "test-secret-only", "access_token_expiry": 3600},
        user_store=store,
        attempt_limiter=limiter,
    )


def _service_with_user(limiter=None, mfa=False):
    svc = _make_service(limiter=limiter)
    secret = pyotp.random_base32() if mfa else ""
    svc.user_store.add(
        UserRecord(
            user_id="u1",
            organization_id="org1",
            email="user@example.com",
            password_hash=svc.hash_password(PASSWORD),
            mfa_enabled=mfa,
            mfa_secret=secret,
        )
    )
    return svc, secret


class TestLoginLockout:
    def test_account_locks_after_threshold_failures(self):
        """Regression for #2703 — unlimited guessing is no longer possible."""
        svc, _ = _service_with_user()

        for _ in range(5):
            result = svc.authenticate_user("user@example.com", "wrong")
            assert result.success is False

        locked = svc.authenticate_user("user@example.com", "wrong")
        assert locked.rate_limited is True
        assert locked.retry_after_seconds > 0

    def test_correct_password_refused_while_locked(self):
        """A lockout must hold even for the real password, or it buys nothing."""
        svc, _ = _service_with_user()
        for _ in range(5):
            svc.authenticate_user("user@example.com", "wrong")

        result = svc.authenticate_user("user@example.com", PASSWORD)
        assert result.success is False
        assert result.rate_limited is True

    def test_bcrypt_not_invoked_while_locked(self, monkeypatch):
        """Locked attempts must cost no hashing work — that is the DoS angle."""
        svc, _ = _service_with_user()
        for _ in range(5):
            svc.authenticate_user("user@example.com", "wrong")

        calls = []
        monkeypatch.setattr(
            svc, "verify_password", lambda *a: calls.append(1) or False
        )
        svc.authenticate_user("user@example.com", PASSWORD)
        assert calls == []

    def test_success_resets_the_counter(self):
        svc, _ = _service_with_user()
        for _ in range(4):
            svc.authenticate_user("user@example.com", "wrong")

        assert svc.authenticate_user("user@example.com", PASSWORD).success is True

        # Budget is full again, so four more failures must not lock.
        for _ in range(4):
            assert svc.authenticate_user("user@example.com", "wrong").rate_limited is False

    def test_unknown_account_is_also_counted(self):
        """Otherwise enumerating usernames is free."""
        svc, _ = _service_with_user()
        for _ in range(5):
            svc.authenticate_user("nobody@example.com", "wrong")

        result = svc.authenticate_user("nobody@example.com", "wrong")
        assert result.rate_limited is True

    def test_lockout_message_does_not_reveal_account_existence(self):
        svc, _ = _service_with_user()
        for _ in range(6):
            real = svc.authenticate_user("user@example.com", "wrong")
        for _ in range(6):
            fake = svc.authenticate_user("ghost@example.com", "wrong")

        assert real.rate_limited and fake.rate_limited
        assert real.error == fake.error

    def test_email_case_and_whitespace_share_one_budget(self):
        """Otherwise each capitalisation is a fresh allowance."""
        svc, _ = _service_with_user()
        variants = [
            "user@example.com",
            "USER@example.com",
            "  User@Example.com  ",
            "uSeR@ExAmPlE.cOm",
            "User@example.com",
        ]
        for email in variants:
            svc.authenticate_user(email, "wrong")

        assert svc.authenticate_user("user@example.com", "wrong").rate_limited is True

    def test_locking_one_account_does_not_lock_another(self):
        svc, _ = _service_with_user()
        svc.user_store.add(
            UserRecord(
                user_id="u2",
                organization_id="org1",
                email="other@example.com",
                password_hash=svc.hash_password(PASSWORD),
            )
        )
        for _ in range(6):
            svc.authenticate_user("user@example.com", "wrong")

        assert svc.authenticate_user("other@example.com", PASSWORD).success is True


class TestAddressLockout:
    def test_address_budget_is_independent_of_account(self):
        """A spray across many accounts from one host still gets stopped."""
        svc, _ = _service_with_user()
        for i in range(20):
            svc.authenticate_user(f"victim{i}@example.com", "wrong", ip_address="10.0.0.9")

        result = svc.authenticate_user("fresh@example.com", "wrong", ip_address="10.0.0.9")
        assert result.rate_limited is True

    def test_other_addresses_unaffected(self):
        svc, _ = _service_with_user()
        for i in range(20):
            svc.authenticate_user(f"v{i}@example.com", "wrong", ip_address="10.0.0.9")

        assert (
            svc.authenticate_user("user@example.com", PASSWORD, ip_address="10.0.0.10").success
            is True
        )

    def test_missing_address_still_applies_account_budget(self):
        svc, _ = _service_with_user()
        for _ in range(6):
            svc.authenticate_user("user@example.com", "wrong", ip_address=None)
        assert svc.authenticate_user("user@example.com", "wrong").rate_limited is True

    def test_both_budgets_charged_on_a_single_failure(self):
        limiter = InMemoryAttemptLimiter()
        svc, _ = _service_with_user(limiter=limiter)
        svc.authenticate_user("user@example.com", "wrong", ip_address="10.0.0.1")

        assert limiter.check("user@example.com", SCOPE_ACCOUNT).failures == 1
        assert limiter.check("10.0.0.1", SCOPE_ADDRESS).failures == 1


class TestTotpLockout:
    def _pending(self, svc):
        return svc.mfa_pending_store.issue("u1")

    def test_totp_locks_after_threshold(self):
        svc, _ = _service_with_user(mfa=True)
        for _ in range(5):
            svc.verify_mfa("u1", self._pending(svc), "000000")

        result = svc.verify_mfa("u1", self._pending(svc), "000000")
        assert result.rate_limited is True

    def test_correct_totp_refused_while_locked(self):
        svc, secret = _service_with_user(mfa=True)
        for _ in range(5):
            svc.verify_mfa("u1", self._pending(svc), "000000")

        result = svc.verify_mfa("u1", self._pending(svc), pyotp.TOTP(secret).now())
        assert result.success is False
        assert result.rate_limited is True

    def test_totp_success_resets_counter(self):
        svc, secret = _service_with_user(mfa=True)
        for _ in range(3):
            svc.verify_mfa("u1", self._pending(svc), "000000")

        assert svc.verify_mfa("u1", self._pending(svc), pyotp.TOTP(secret).now()).success is True

        for _ in range(3):
            assert svc.verify_mfa("u1", self._pending(svc), "000000").rate_limited is False

    def test_totp_budget_is_separate_from_password_budget(self):
        """Exhausting one must not consume the other."""
        svc, secret = _service_with_user(mfa=True)
        for _ in range(5):
            svc.verify_mfa("u1", self._pending(svc), "000000")

        # The password budget for this account is untouched.
        result = svc.authenticate_user("user@example.com", PASSWORD)
        assert result.mfa_required is True

    def test_totp_budget_is_tighter_than_address_budget(self):
        limiter = InMemoryAttemptLimiter()
        assert limiter.threshold_for(SCOPE_TOTP) < limiter.threshold_for(SCOPE_ADDRESS)


class TestBackoff:
    def test_backoff_grows_with_repeated_lockouts(self):
        limiter = InMemoryAttemptLimiter(backoff_schedule=(60, 120, 300))
        durations = []
        for _ in range(3):
            for _ in range(5):
                state = limiter.record_failure("acct", SCOPE_ACCOUNT)
            durations.append(state.retry_after_seconds)
            limiter._buckets["account:acct"].locked_until = None

        assert durations == [60, 120, 300]

    def test_backoff_caps_at_the_last_step(self):
        limiter = InMemoryAttemptLimiter(backoff_schedule=(60, 120))
        for _ in range(4):
            for _ in range(5):
                state = limiter.record_failure("acct", SCOPE_ACCOUNT)
            limiter._buckets["account:acct"].locked_until = None
        assert state.retry_after_seconds == 120

    def test_empty_backoff_schedule_is_rejected(self):
        with pytest.raises(ValueError, match="at least one duration"):
            InMemoryAttemptLimiter(backoff_schedule=())

    def test_stale_failures_decay(self):
        """An occasional typo must not accumulate into a lockout."""
        from datetime import datetime, timedelta, timezone

        limiter = InMemoryAttemptLimiter(decay_seconds=60)
        for _ in range(4):
            limiter.record_failure("acct", SCOPE_ACCOUNT)

        bucket = limiter._buckets["account:acct"]
        bucket.last_failure_at = datetime.now(timezone.utc) - timedelta(seconds=120)

        state = limiter.record_failure("acct", SCOPE_ACCOUNT)
        assert state.locked is False
        assert state.failures == 1


class TestInMemoryLimiter:
    def test_empty_identity_is_never_locked(self):
        limiter = InMemoryAttemptLimiter()
        assert limiter.check("", SCOPE_ACCOUNT).locked is False
        assert limiter.record_failure("", SCOPE_ACCOUNT).locked is False
        limiter.record_success("", SCOPE_ACCOUNT)

    def test_unknown_identity_reports_full_budget(self):
        limiter = InMemoryAttemptLimiter()
        state = limiter.check("nobody", SCOPE_ACCOUNT)
        assert state.locked is False
        assert state.failures_remaining == limiter.threshold_for(SCOPE_ACCOUNT)

    def test_failures_remaining_counts_down(self):
        limiter = InMemoryAttemptLimiter()
        limiter.record_failure("acct", SCOPE_ACCOUNT)
        limiter.record_failure("acct", SCOPE_ACCOUNT)
        assert limiter.check("acct", SCOPE_ACCOUNT).failures_remaining == 3

    def test_scopes_do_not_collide(self):
        """The same string used as an account and an address stays separate."""
        limiter = InMemoryAttemptLimiter()
        for _ in range(6):
            limiter.record_failure("shared", SCOPE_ACCOUNT)
        assert limiter.check("shared", SCOPE_ACCOUNT).locked is True
        assert limiter.check("shared", SCOPE_ADDRESS).locked is False

    def test_idle_buckets_are_purged(self):
        """Otherwise guessing usernames grows the map without bound."""
        from datetime import datetime, timedelta, timezone

        limiter = InMemoryAttemptLimiter(decay_seconds=60)
        limiter.record_failure("transient", SCOPE_ACCOUNT)
        limiter._buckets["account:transient"].last_failure_at = (
            datetime.now(timezone.utc) - timedelta(seconds=600)
        )
        limiter.check("someone-else", SCOPE_ACCOUNT)
        assert "account:transient" not in limiter._buckets

    def test_locked_buckets_survive_the_purge(self):
        from datetime import datetime, timedelta, timezone

        limiter = InMemoryAttemptLimiter(decay_seconds=1)
        for _ in range(5):
            limiter.record_failure("locked-acct", SCOPE_ACCOUNT)
        limiter._buckets["account:locked-acct"].last_failure_at = (
            datetime.now(timezone.utc) - timedelta(seconds=600)
        )
        assert limiter.check("locked-acct", SCOPE_ACCOUNT).locked is True

    def test_clear_resets_state(self):
        limiter = InMemoryAttemptLimiter()
        for _ in range(6):
            limiter.record_failure("acct", SCOPE_ACCOUNT)
        limiter.clear()
        assert limiter.check("acct", SCOPE_ACCOUNT).locked is False

    def test_reports_itself_as_process_local(self):
        assert InMemoryAttemptLimiter().is_shared is False

    def test_concurrent_failures_lock_exactly_once(self):
        limiter = InMemoryAttemptLimiter()
        barrier = threading.Barrier(10)
        results = []

        def attempt():
            barrier.wait()
            results.append(limiter.record_failure("contended", SCOPE_ACCOUNT))

        threads = [threading.Thread(target=attempt) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(1 for r in results if r.locked) >= 1
        assert limiter.check("contended", SCOPE_ACCOUNT).locked is True


class _BrokenRedis:
    def ttl(self, *a, **k):
        raise ConnectionError("redis is down")

    def get(self, *a, **k):
        raise ConnectionError("redis is down")

    def eval(self, *a, **k):
        raise ConnectionError("redis is down")

    def delete(self, *a, **k):
        raise ConnectionError("redis is down")


class TestRedisLimiterFailsClosed:
    """Unlike the general rate limiter, auth throttling must not fail open."""

    @pytest.fixture
    def broken(self, monkeypatch):
        limiter = RedisAttemptLimiter()
        monkeypatch.setattr(limiter, "_client", lambda: _BrokenRedis())
        return limiter

    def test_check_fails_closed(self, broken):
        assert broken.check("acct", SCOPE_ACCOUNT).locked is True

    def test_record_failure_fails_closed(self, broken):
        assert broken.record_failure("acct", SCOPE_ACCOUNT).locked is True

    def test_failed_reset_does_not_raise_into_the_login_path(self, broken):
        """A stale counter only makes the limiter stricter — never fatal."""
        broken.record_success("acct", SCOPE_ACCOUNT)

    def test_login_is_refused_when_the_limiter_is_down(self, monkeypatch):
        limiter = RedisAttemptLimiter()
        monkeypatch.setattr(limiter, "_client", lambda: _BrokenRedis())
        svc, _ = _service_with_user(limiter=limiter)

        result = svc.authenticate_user("user@example.com", PASSWORD)
        assert result.success is False
        assert result.rate_limited is True

    def test_reports_itself_as_shared(self):
        assert RedisAttemptLimiter().is_shared is True


class TestSharedLimiterAcrossWorkers:
    def test_two_services_sharing_a_limiter_share_the_budget(self):
        """Models two uvicorn workers behind one Redis."""
        shared = InMemoryAttemptLimiter()
        worker_a, _ = _service_with_user(limiter=shared)
        worker_b = _make_service(limiter=shared)
        worker_b.user_store = worker_a.user_store

        for _ in range(3):
            worker_a.authenticate_user("user@example.com", "wrong")
        for _ in range(2):
            worker_b.authenticate_user("user@example.com", "wrong")

        assert worker_b.authenticate_user("user@example.com", PASSWORD).rate_limited is True

    def test_separate_limiters_multiply_the_budget(self):
        """Documents why the in-memory backend warns on multi-worker use."""
        worker_a, _ = _service_with_user()
        worker_b = _make_service()
        worker_b.user_store = worker_a.user_store

        for _ in range(6):
            worker_a.authenticate_user("user@example.com", "wrong")

        assert worker_b.authenticate_user("user@example.com", PASSWORD).success is True


class TestBuildAttemptLimiter:
    def test_memory_backend(self):
        assert isinstance(build_attempt_limiter("memory"), InMemoryAttemptLimiter)

    def test_redis_backend(self):
        assert isinstance(
            build_attempt_limiter("redis", "redis://localhost:6379/0"),
            RedisAttemptLimiter,
        )

    def test_name_is_case_and_space_insensitive(self):
        assert isinstance(build_attempt_limiter("  REDIS "), RedisAttemptLimiter)

    def test_unknown_backend_falls_back_to_memory(self, caplog):
        limiter = build_attempt_limiter("postgres")
        assert isinstance(limiter, InMemoryAttemptLimiter)
        assert "Unknown attempt limiter backend" in caplog.text

    def test_none_defaults_to_memory(self):
        assert isinstance(build_attempt_limiter(None), InMemoryAttemptLimiter)

    def test_implementations_satisfy_the_interface(self):
        for limiter in (InMemoryAttemptLimiter(), RedisAttemptLimiter()):
            assert isinstance(limiter, AuthAttemptLimiter)


class TestLoginEndpoint:
    """The HTTP contract: 429 with Retry-After, distinct from 401."""

    @pytest.fixture
    def client(self, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        import src.saas.routes.auth as auth_routes

        svc, _ = _service_with_user()
        monkeypatch.setattr(auth_routes, "_AUTH_SERVICE", svc)

        app = FastAPI()
        app.include_router(auth_routes.router)
        return TestClient(app)

    def _login(self, client, password):
        return client.post(
            "/api/v1/auth/login",
            json={"username": "user@example.com", "password": password},
        )

    def test_wrong_password_returns_401(self, client):
        assert self._login(client, "wrong").status_code == 401

    def test_lockout_returns_429_not_401(self, client):
        """A client must be able to tell "wrong password" from "stop trying"."""
        for _ in range(5):
            self._login(client, "wrong")
        response = self._login(client, "wrong")
        assert response.status_code == 429

    def test_429_carries_retry_after_header(self, client):
        for _ in range(6):
            response = self._login(client, "wrong")
        assert int(response.headers["Retry-After"]) > 0

    def test_429_body_uses_the_platform_error_shape(self, client):
        for _ in range(6):
            response = self._login(client, "wrong")
        detail = response.json()["detail"]
        assert detail["error"]["code"] == "RATE_LIMIT_EXCEEDED"
        assert detail["error"]["details"]["limit_type"] == "authentication"

    def test_successful_login_still_works(self, client):
        assert self._login(client, PASSWORD).status_code == 200

    def test_password_reset_is_throttled(self, client):
        for _ in range(5):
            client.post("/api/v1/auth/password/reset", json={"email": "user@example.com"})
        response = client.post(
            "/api/v1/auth/password/reset", json={"email": "user@example.com"}
        )
        assert response.status_code == 429
        assert response.json()["detail"]["error"]["details"]["limit_type"] == "password_reset"

    def test_password_reset_response_is_uniform_before_throttling(self, client):
        known = client.post("/api/v1/auth/password/reset", json={"email": "user@example.com"})
        unknown = client.post("/api/v1/auth/password/reset", json={"email": "ghost@example.com"})
        assert known.json() == unknown.json()


class TestServiceDefaults:
    def test_default_limiter_is_in_memory(self):
        assert isinstance(_make_service().attempt_limiter, InMemoryAttemptLimiter)

    def test_process_local_limiter_warns(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING, logger="src.saas.auth.service"):
            _make_service()
        assert "process-local" in caplog.text

    def test_lockout_state_defaults_are_unlocked(self):
        state = LockoutState(locked=False)
        assert state.retry_after_seconds == 0
        assert state.failures == 0
