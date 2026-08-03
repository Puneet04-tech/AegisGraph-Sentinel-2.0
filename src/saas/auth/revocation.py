"""Token and session revocation stores.

AegisGraph Sentinel Enterprise

When a user logs out, the session must end — not just the access token that
happened to be presented on the logout request.  ``AuthService`` mints an
access token and a refresh token together in :meth:`_create_auth_result`, and
both carry the same ``session_id``.  Revoking that session id is what makes
logout terminate every credential issued for it.

Three properties matter here and each is enforced by a store implementation
rather than by the caller:

Session-level revocation
    Revoking a session invalidates the access token *and* the refresh token
    issued alongside it.  Revoking a lone ``jti`` cannot do this, because the
    logout request only ever carries the access token.

Refresh rotation with replay detection
    A refresh token is single-use.  :meth:`consume_refresh_jti` succeeds once
    and fails on every later presentation of the same ``jti``.  A second
    presentation means the token was captured, so the whole session family is
    revoked rather than just the replayed token.

Fail closed
    If the backing store cannot be reached, the read paths report *revoked*.
    This is the opposite of :mod:`src.security.rate_limit`, which deliberately
    fails open — dropping a request there is worse than allowing an extra one.
    For revocation the trade is reversed: allowing a request we cannot vouch
    for is exactly the failure this module exists to prevent.

``InMemoryTokenRevocationStore`` is the default so tests and local development
work with no external service.  It is per-process, so a deployment running more
than one worker must configure ``RedisTokenRevocationStore``; ``AuthService``
warns at startup when that is not the case.
"""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Namespaces for the Redis key space. Kept distinct so a session revocation can
# never be mistaken for a token revocation when scanning or debugging.
_TOKEN_PREFIX = "aegis:revoked:token:"
_SESSION_PREFIX = "aegis:revoked:session:"
_REFRESH_PREFIX = "aegis:refresh:used:"

# Floor applied to every computed TTL. A token whose expiry has already passed
# still gets a short-lived tombstone so a clock skew of a few seconds between
# workers cannot open a replay window.
_MIN_TTL_SECONDS = 60


def _ttl_seconds(expires_at: Optional[datetime]) -> int:
    """Return the seconds a revocation entry must outlive.

    An entry only needs to exist for as long as the token it names would
    otherwise have validated; past that point the signature check rejects it
    anyway and keeping the record wastes memory.  ``None`` means the caller
    could not determine an expiry, in which case we fall back to the floor
    rather than storing the entry forever.
    """
    if expires_at is None:
        return _MIN_TTL_SECONDS
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    remaining = (expires_at - datetime.now(timezone.utc)).total_seconds()
    return max(_MIN_TTL_SECONDS, int(remaining) + 1)


class TokenRevocationStore(ABC):
    """Abstract revocation store.

    Concrete implementations back this with a process-local dictionary or with
    Redis.  Mirrors the ``UserStore`` / ``MFAPendingStore`` interfaces already
    defined in :mod:`src.saas.auth.service`.
    """

    @abstractmethod
    def revoke_token(self, jti: str, expires_at: Optional[datetime] = None) -> None:
        """Revoke a single token id."""

    @abstractmethod
    def revoke_session(self, session_id: str, expires_at: Optional[datetime] = None) -> None:
        """Revoke every token issued for *session_id*."""

    @abstractmethod
    def is_token_revoked(self, jti: str) -> bool:
        """Return True if *jti* was revoked, or if the store is unreachable."""

    @abstractmethod
    def is_session_revoked(self, session_id: str) -> bool:
        """Return True if *session_id* was revoked, or if the store is unreachable."""

    @abstractmethod
    def consume_refresh_jti(
        self,
        jti: str,
        session_id: str,
        expires_at: Optional[datetime] = None,
    ) -> bool:
        """Single-use-consume a refresh token id.

        Return True on the first presentation of *jti*.  Return False on any
        later presentation and revoke *session_id*, because a replayed refresh
        token means the credential is held by more than one party.
        """

    @property
    def is_shared(self) -> bool:
        """Whether revocations are visible to other worker processes.

        In-memory stores answer False, which lets ``AuthService`` warn when a
        multi-worker deployment would otherwise be silently bypassable.
        """
        return False


class InMemoryTokenRevocationStore(TokenRevocationStore):
    """Thread-safe, TTL-bounded in-process revocation store.

    Suitable for tests and single-process local development.  Do **not** use in
    a multi-worker deployment: a logout handled by one worker is invisible to
    the others, so the token stays live on every process that did not see it.

    Entries carry an expiry and are swept lazily on access, so the store does
    not grow without bound the way a plain ``set`` of revoked ids would.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tokens: Dict[str, datetime] = {}
        self._sessions: Dict[str, datetime] = {}
        self._used_refresh: Dict[str, datetime] = {}

    # -- internal ---------------------------------------------------------

    def _expiry_from_ttl(self, expires_at: Optional[datetime]) -> datetime:
        return datetime.now(timezone.utc) + timedelta(seconds=_ttl_seconds(expires_at))

    def _purge_expired(self) -> None:
        """Drop entries whose underlying token can no longer validate.

        Caller must hold ``self._lock``.
        """
        now = datetime.now(timezone.utc)
        for bucket in (self._tokens, self._sessions, self._used_refresh):
            expired = [key for key, expiry in bucket.items() if expiry <= now]
            for key in expired:
                del bucket[key]

    def _contains(self, bucket: Dict[str, datetime], key: str) -> bool:
        with self._lock:
            self._purge_expired()
            return key in bucket

    # -- interface --------------------------------------------------------

    def revoke_token(self, jti: str, expires_at: Optional[datetime] = None) -> None:
        if not jti:
            return
        with self._lock:
            self._purge_expired()
            self._tokens[jti] = self._expiry_from_ttl(expires_at)

    def revoke_session(self, session_id: str, expires_at: Optional[datetime] = None) -> None:
        if not session_id:
            return
        with self._lock:
            self._purge_expired()
            self._sessions[session_id] = self._expiry_from_ttl(expires_at)

    def is_token_revoked(self, jti: str) -> bool:
        if not jti:
            return False
        return self._contains(self._tokens, jti)

    def is_session_revoked(self, session_id: str) -> bool:
        if not session_id:
            return False
        return self._contains(self._sessions, session_id)

    def consume_refresh_jti(
        self,
        jti: str,
        session_id: str,
        expires_at: Optional[datetime] = None,
    ) -> bool:
        if not jti:
            return False
        with self._lock:
            self._purge_expired()
            if jti in self._used_refresh:
                # Replay. The legitimate holder already rotated this token, so
                # whoever presented it a second time is not the only party
                # holding it — burn the whole family.
                self._sessions[session_id] = self._expiry_from_ttl(expires_at)
                logger.warning(
                    "Refresh token replay detected; revoking session %s", session_id
                )
                return False
            self._used_refresh[jti] = self._expiry_from_ttl(expires_at)
            return True

    def clear(self) -> None:
        """Drop all state. Intended for use in tests."""
        with self._lock:
            self._tokens.clear()
            self._sessions.clear()
            self._used_refresh.clear()


class RedisTokenRevocationStore(TokenRevocationStore):
    """Redis-backed revocation store shared across workers and restarts.

    Keys are written with ``SETEX`` so Redis expiry reclaims them; there is no
    sweep to run and no unbounded growth.  Rotation uses ``SET NX``, which is
    atomic, so two concurrent refreshes of the same token cannot both succeed.

    Every read path fails **closed**: a Redis error is reported as "revoked".
    A user is signed out and retries; the alternative is honouring a token we
    cannot confirm is still valid, which defeats the point of the store.
    """

    def __init__(self, redis_url: Optional[str] = None) -> None:
        self._redis_url = redis_url

    def _client(self):
        from src.utils.redis_client import get_redis_client

        return get_redis_client(self._redis_url)

    @property
    def is_shared(self) -> bool:
        return True

    def revoke_token(self, jti: str, expires_at: Optional[datetime] = None) -> None:
        if not jti:
            return
        try:
            self._client().setex(f"{_TOKEN_PREFIX}{jti}", _ttl_seconds(expires_at), "1")
        except Exception as exc:
            # A revocation that does not land is a token that stays live, so
            # this must surface rather than be swallowed.
            logger.error("Failed to record token revocation for %s: %s", jti, exc)
            raise

    def revoke_session(self, session_id: str, expires_at: Optional[datetime] = None) -> None:
        if not session_id:
            return
        try:
            self._client().setex(
                f"{_SESSION_PREFIX}{session_id}", _ttl_seconds(expires_at), "1"
            )
        except Exception as exc:
            logger.error(
                "Failed to record session revocation for %s: %s", session_id, exc
            )
            raise

    def is_token_revoked(self, jti: str) -> bool:
        if not jti:
            return False
        try:
            return bool(self._client().exists(f"{_TOKEN_PREFIX}{jti}"))
        except Exception as exc:
            logger.error("Revocation store unreachable, failing closed: %s", exc)
            return True

    def is_session_revoked(self, session_id: str) -> bool:
        if not session_id:
            return False
        try:
            return bool(self._client().exists(f"{_SESSION_PREFIX}{session_id}"))
        except Exception as exc:
            logger.error("Revocation store unreachable, failing closed: %s", exc)
            return True

    def consume_refresh_jti(
        self,
        jti: str,
        session_id: str,
        expires_at: Optional[datetime] = None,
    ) -> bool:
        if not jti:
            return False
        ttl = _ttl_seconds(expires_at)
        try:
            first_use = self._client().set(
                f"{_REFRESH_PREFIX}{jti}", "1", nx=True, ex=ttl
            )
        except Exception as exc:
            logger.error("Revocation store unreachable, failing closed: %s", exc)
            return False

        if first_use:
            return True

        logger.warning(
            "Refresh token replay detected; revoking session %s", session_id
        )
        try:
            self.revoke_session(session_id, expires_at)
        except Exception:
            # Already logged by revoke_session. The refusal below still stands,
            # so the replayed token is rejected regardless.
            pass
        return False


def build_revocation_store(
    backend: str = "memory",
    redis_url: Optional[str] = None,
) -> TokenRevocationStore:
    """Return the revocation store named by *backend*.

    Unknown backends fall back to the in-memory store with a warning rather
    than raising, so a typo in configuration degrades to a working (if
    process-local) service instead of refusing to boot.
    """
    normalized = (backend or "memory").strip().lower()
    if normalized == "redis":
        return RedisTokenRevocationStore(redis_url)
    if normalized not in ("memory", "in_memory", "inmemory"):
        logger.warning(
            "Unknown revocation backend %r; falling back to in-memory store", backend
        )
    return InMemoryTokenRevocationStore()
