"""Failed-authentication tracking and account lockout.

AegisGraph Sentinel Enterprise

The authentication endpoints answer every request as fast as a caller can send
one, which makes password spraying and TOTP brute force bounded only by network
throughput.  This module supplies the counter that was missing.

Two budgets are tracked independently and both must pass:

Per account
    Stops a single account being sprayed regardless of how many source
    addresses the attacker rotates through.

Per source address
    Stops one host working through a list of accounts.

A third, tighter budget covers TOTP verification.  The code space is 10^6 and
``verify_mfa_token`` accepts a clock-drift window, so roughly three codes are
valid at any instant — without a dedicated budget the second factor falls in
minutes.

Two policies here differ deliberately from :mod:`src.security.rate_limit`:

Fail closed
    If the backing store is unreachable, attempts are refused rather than
    waved through.  The general limiter fails open because dropping a scoring
    request is worse than allowing an extra one; for authentication the trade
    is reversed, since failing open removes the only barrier at exactly the
    moment operators are distracted by an outage.

Check before hashing
    :meth:`check` is consulted *before* the bcrypt comparison, so a locked
    account costs no CPU.  Unbounded attempts against a bcrypt endpoint are a
    denial-of-service in their own right — they starve the fraud-scoring thread
    pool that shares the process.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Namespaces for the Redis key space, kept distinct per scope so an account
# lockout and an address lockout cannot collide.
_KEY_PREFIX = "aegis:auth:attempts:"

# Scope names. Callers pass these rather than free strings so a typo cannot
# silently create a fresh, empty budget.
SCOPE_ACCOUNT = "account"
SCOPE_ADDRESS = "address"
SCOPE_TOTP = "totp"
SCOPE_PASSWORD_RESET = "password_reset"

# Consecutive failures tolerated before the first lockout, per scope.
_DEFAULT_THRESHOLDS: Dict[str, int] = {
    SCOPE_ACCOUNT: 5,
    SCOPE_ADDRESS: 20,
    SCOPE_TOTP: 5,
    # Reset requests are cheap relative to bcrypt login, but still need a
    # dedicated budget so spraying /password/reset cannot lock account login.
    SCOPE_PASSWORD_RESET: 5,
}

# Lockout duration in seconds, indexed by how many lockouts this identity has
# already triggered. The last entry repeats, so backoff grows and then caps
# rather than escalating without bound.
_DEFAULT_BACKOFF: Tuple[int, ...] = (60, 120, 300, 900, 1800)

# How long a failure count survives without further failures. A user who
# mistypes a password twice today should not start tomorrow one attempt from
# lockout.
_DEFAULT_DECAY_SECONDS = 900


@dataclass(frozen=True)
class LockoutState:
    """Outcome of consulting a budget."""

    locked: bool
    retry_after_seconds: int = 0
    failures: int = 0
    failures_remaining: int = 0


_UNLOCKED = LockoutState(locked=False)


class AuthAttemptLimiter:
    """Base limiter defining the policy shared by all backends.

    Subclasses implement storage only; thresholds, backoff, and decay live
    here so every backend enforces identical policy.
    """

    def __init__(
        self,
        thresholds: Optional[Dict[str, int]] = None,
        backoff_schedule: Tuple[int, ...] = _DEFAULT_BACKOFF,
        decay_seconds: int = _DEFAULT_DECAY_SECONDS,
    ) -> None:
        self.thresholds = {**_DEFAULT_THRESHOLDS, **(thresholds or {})}
        if not backoff_schedule:
            raise ValueError("backoff_schedule must contain at least one duration")
        self.backoff_schedule = backoff_schedule
        self.decay_seconds = decay_seconds

    def threshold_for(self, scope: str) -> int:
        return self.thresholds.get(scope, _DEFAULT_THRESHOLDS[SCOPE_ACCOUNT])

    def _lockout_duration(self, lockout_count: int) -> int:
        """Return the lockout length for the *lockout_count*-th offence."""
        index = min(max(lockout_count, 1) - 1, len(self.backoff_schedule) - 1)
        return self.backoff_schedule[index]

    @property
    def is_shared(self) -> bool:
        """Whether lockouts are visible to other worker processes."""
        return False

    def check(self, identity: str, scope: str = SCOPE_ACCOUNT) -> LockoutState:
        raise NotImplementedError

    def record_failure(self, identity: str, scope: str = SCOPE_ACCOUNT) -> LockoutState:
        raise NotImplementedError

    def record_success(self, identity: str, scope: str = SCOPE_ACCOUNT) -> None:
        raise NotImplementedError


@dataclass
class _Bucket:
    """Per-identity counter state."""

    failures: int = 0
    lockout_count: int = 0
    locked_until: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None


class InMemoryAttemptLimiter(AuthAttemptLimiter):
    """Thread-safe in-process limiter for tests and single-process deployments.

    Do **not** use with more than one worker: an attacker's attempts spread
    across N processes each get the full budget, multiplying the real threshold
    by N. ``AuthService`` warns when this backend is active.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._lock = threading.RLock()
        self._buckets: Dict[str, _Bucket] = {}

    def _key(self, identity: str, scope: str) -> str:
        return f"{scope}:{identity}"

    def _purge_expired(self, now: datetime) -> None:
        """Drop buckets that are neither locked nor recently active.

        Caller must hold ``self._lock``. Without this the map would grow by one
        entry per distinct username an attacker guesses, which is itself a
        memory-exhaustion vector.
        """
        stale = []
        for key, bucket in self._buckets.items():
            if bucket.locked_until and bucket.locked_until > now:
                continue
            last = bucket.last_failure_at
            if last is None or (now - last).total_seconds() > self.decay_seconds:
                stale.append(key)
        for key in stale:
            del self._buckets[key]

    def _state(self, bucket: _Bucket, scope: str, now: datetime) -> LockoutState:
        if bucket.locked_until and bucket.locked_until > now:
            return LockoutState(
                locked=True,
                retry_after_seconds=max(
                    1, int((bucket.locked_until - now).total_seconds())
                ),
                failures=bucket.failures,
                failures_remaining=0,
            )
        threshold = self.threshold_for(scope)
        return LockoutState(
            locked=False,
            failures=bucket.failures,
            failures_remaining=max(0, threshold - bucket.failures),
        )

    def check(self, identity: str, scope: str = SCOPE_ACCOUNT) -> LockoutState:
        if not identity:
            return _UNLOCKED
        now = datetime.now(timezone.utc)
        with self._lock:
            self._purge_expired(now)
            bucket = self._buckets.get(self._key(identity, scope))
            if bucket is None:
                return LockoutState(
                    locked=False, failures_remaining=self.threshold_for(scope)
                )
            return self._state(bucket, scope, now)

    def record_failure(self, identity: str, scope: str = SCOPE_ACCOUNT) -> LockoutState:
        if not identity:
            return _UNLOCKED
        now = datetime.now(timezone.utc)
        with self._lock:
            self._purge_expired(now)
            key = self._key(identity, scope)
            bucket = self._buckets.setdefault(key, _Bucket())

            # A lapse longer than the decay window starts a fresh count, so an
            # occasional typo never accumulates into a lockout.
            if (
                bucket.last_failure_at
                and (now - bucket.last_failure_at).total_seconds() > self.decay_seconds
            ):
                bucket.failures = 0

            bucket.failures += 1
            bucket.last_failure_at = now

            if bucket.failures >= self.threshold_for(scope):
                bucket.lockout_count += 1
                duration = self._lockout_duration(bucket.lockout_count)
                bucket.locked_until = now + timedelta(seconds=duration)
                bucket.failures = 0
                logger.warning(
                    "Authentication lockout triggered (scope=%s, offence=%d, "
                    "duration=%ds)",
                    scope,
                    bucket.lockout_count,
                    duration,
                )
                return LockoutState(
                    locked=True,
                    retry_after_seconds=duration,
                    failures=0,
                    failures_remaining=0,
                )

            return self._state(bucket, scope, now)

    def record_success(self, identity: str, scope: str = SCOPE_ACCOUNT) -> None:
        if not identity:
            return
        with self._lock:
            self._buckets.pop(self._key(identity, scope), None)

    def clear(self) -> None:
        """Drop all state. Intended for use in tests."""
        with self._lock:
            self._buckets.clear()


class RedisAttemptLimiter(AuthAttemptLimiter):
    """Redis-backed limiter shared across workers and surviving restart.

    The counter and its expiry are set together inside a Lua script so a
    process dying between ``INCR`` and ``EXPIRE`` cannot leave a counter that
    never decays.  Reads fail **closed**.
    """

    # KEYS[1] failure counter, KEYS[2] lockout marker, KEYS[3] offence counter.
    # Returns {locked, retry_after, failures}.
    _RECORD_FAILURE_LUA = """
    local fail_key = KEYS[1]
    local lock_key = KEYS[2]
    local offence_key = KEYS[3]
    local threshold = tonumber(ARGV[1])
    local decay = tonumber(ARGV[2])
    local offence_ttl = tonumber(ARGV[3])

    local existing = redis.call('TTL', lock_key)
    if existing > 0 then
      return {1, existing, 0}
    end

    local failures = redis.call('INCR', fail_key)
    redis.call('EXPIRE', fail_key, decay)

    if failures < threshold then
      return {0, 0, failures}
    end

    local offences = redis.call('INCR', offence_key)
    redis.call('EXPIRE', offence_key, offence_ttl)
    local duration = tonumber(ARGV[3 + offences])
    if duration == nil then
      duration = tonumber(ARGV[table.getn(ARGV)])
    end

    redis.call('SET', lock_key, '1', 'EX', duration)
    redis.call('DEL', fail_key)
    return {1, duration, 0}
    """

    def __init__(self, redis_url: Optional[str] = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._redis_url = redis_url

    def _client(self):
        from src.utils.redis_client import get_redis_client

        return get_redis_client(self._redis_url)

    @property
    def is_shared(self) -> bool:
        return True

    def _keys(self, identity: str, scope: str) -> Tuple[str, str, str]:
        base = f"{_KEY_PREFIX}{scope}:{identity}"
        return f"{base}:fail", f"{base}:lock", f"{base}:offence"

    def check(self, identity: str, scope: str = SCOPE_ACCOUNT) -> LockoutState:
        if not identity:
            return _UNLOCKED
        fail_key, lock_key, _ = self._keys(identity, scope)
        try:
            client = self._client()
            ttl = client.ttl(lock_key)
            if ttl and ttl > 0:
                return LockoutState(locked=True, retry_after_seconds=int(ttl))
            failures = int(client.get(fail_key) or 0)
        except Exception as exc:
            logger.error("Attempt limiter unreachable, failing closed: %s", exc)
            return LockoutState(
                locked=True, retry_after_seconds=self.backoff_schedule[0]
            )
        threshold = self.threshold_for(scope)
        return LockoutState(
            locked=False,
            failures=failures,
            failures_remaining=max(0, threshold - failures),
        )

    def record_failure(self, identity: str, scope: str = SCOPE_ACCOUNT) -> LockoutState:
        if not identity:
            return _UNLOCKED
        fail_key, lock_key, offence_key = self._keys(identity, scope)
        # The offence counter must outlive the longest lockout, otherwise
        # backoff resets to its first step while the identity is still locked.
        offence_ttl = max(self.backoff_schedule) * 4
        args = [
            str(self.threshold_for(scope)),
            str(self.decay_seconds),
            str(offence_ttl),
            *[str(d) for d in self.backoff_schedule],
        ]
        try:
            locked, retry_after, failures = self._client().eval(
                self._RECORD_FAILURE_LUA, 3, fail_key, lock_key, offence_key, *args
            )
        except Exception as exc:
            logger.error("Attempt limiter unreachable, failing closed: %s", exc)
            return LockoutState(
                locked=True, retry_after_seconds=self.backoff_schedule[0]
            )

        if int(locked):
            logger.warning("Authentication lockout triggered (scope=%s)", scope)
            return LockoutState(locked=True, retry_after_seconds=int(retry_after))
        remaining = max(0, self.threshold_for(scope) - int(failures))
        return LockoutState(
            locked=False, failures=int(failures), failures_remaining=remaining
        )

    def record_success(self, identity: str, scope: str = SCOPE_ACCOUNT) -> None:
        if not identity:
            return
        fail_key, _, offence_key = self._keys(identity, scope)
        try:
            self._client().delete(fail_key, offence_key)
        except Exception as exc:
            # Leaving a stale counter only makes the limiter stricter, so a
            # failure here is logged but not raised into the login path.
            logger.warning("Could not reset attempt counter: %s", exc)


def build_attempt_limiter(
    backend: str = "memory",
    redis_url: Optional[str] = None,
) -> AuthAttemptLimiter:
    """Return the limiter named by *backend*.

    Unknown names fall back to the in-memory limiter with a warning, so a
    configuration typo degrades to a working (if process-local) limiter rather
    than preventing startup.
    """
    normalized = (backend or "memory").strip().lower()
    if normalized == "redis":
        return RedisAttemptLimiter(redis_url)
    if normalized not in ("memory", "in_memory", "inmemory"):
        logger.warning(
            "Unknown attempt limiter backend %r; falling back to in-memory", backend
        )
    return InMemoryAttemptLimiter()
