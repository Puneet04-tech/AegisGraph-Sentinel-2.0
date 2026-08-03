"""Persistence for password resets, sessions, and API keys.

AegisGraph Sentinel Enterprise

The credential-lifecycle endpoints in :mod:`src.saas.routes.auth` were written
against Pydantic models with no storage behind them, so they returned success
without doing anything.  This module supplies the three stores they need,
following the ``UserStore`` / ``MFAPendingStore`` ABC pattern already
established in :mod:`src.saas.auth.service`: an interface, an in-memory
implementation for tests and local development, and room for a database-backed
one in production.

Everything secret is stored as a SHA-256 hash and compared with
``secrets.compare_digest``.  Reset tokens and API keys are only ever returned
to the caller once, at creation.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Reset links are emailed, so they linger in inboxes and proxy logs. One hour
# is long enough to be usable and short enough to limit that exposure.
DEFAULT_RESET_TTL_SECONDS = 3600

# Sessions expire on their own so an abandoned device does not stay listed
# forever.
DEFAULT_SESSION_TTL_SECONDS = 86400 * 7


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Password reset tokens
# ---------------------------------------------------------------------------


@dataclass
class ResetTokenRecord:
    """A pending password-reset token."""

    user_id: str
    token_hash: str
    expires_at: datetime
    created_at: datetime = field(default_factory=_now)


class PasswordResetTokenStore(ABC):
    """Abstract store for single-use password-reset tokens."""

    @abstractmethod
    def issue(self, user_id: str) -> str:
        """Generate, store, and return a reset token for *user_id*."""

    @abstractmethod
    def consume(self, token: str) -> Optional[str]:
        """Validate and single-use-consume *token*.

        Returns the owning ``user_id``, or ``None`` when the token is unknown,
        expired, or already used.
        """

    @abstractmethod
    def invalidate_for_user(self, user_id: str) -> None:
        """Drop every outstanding token for *user_id*."""


class InMemoryPasswordResetTokenStore(PasswordResetTokenStore):
    """Thread-safe in-process reset-token store for tests and local dev."""

    def __init__(self, ttl_seconds: int = DEFAULT_RESET_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._lock = threading.RLock()
        # token_hash -> record. Keyed by hash so the raw token is never stored.
        self._tokens: Dict[str, ResetTokenRecord] = {}

    def _purge_expired(self) -> None:
        """Caller must hold self._lock."""
        now = _now()
        for key in [k for k, r in self._tokens.items() if r.expires_at <= now]:
            del self._tokens[key]

    def issue(self, user_id: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._purge_expired()
            # A newly requested reset invalidates earlier ones, so a token from
            # a previous request cannot be used after the user asks again.
            self.invalidate_for_user(user_id)
            self._tokens[_hash(token)] = ResetTokenRecord(
                user_id=user_id,
                token_hash=_hash(token),
                expires_at=_now() + timedelta(seconds=self._ttl_seconds),
            )
        return token

    def consume(self, token: str) -> Optional[str]:
        if not token:
            return None
        token_hash = _hash(token)
        with self._lock:
            self._purge_expired()
            record = self._tokens.pop(token_hash, None)
            if record is None:
                return None
            if record.expires_at <= _now():
                return None
            if not secrets.compare_digest(record.token_hash, token_hash):
                return None  # pragma: no cover - dict lookup already matched
            return record.user_id

    def invalidate_for_user(self, user_id: str) -> None:
        with self._lock:
            for key in [k for k, r in self._tokens.items() if r.user_id == user_id]:
                del self._tokens[key]


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


@dataclass
class SessionRecord:
    """A signed-in session, as shown on the account's sessions list."""

    session_id: str
    user_id: str
    device: str = "Unknown device"
    ip_address: str = "unknown"
    created_at: datetime = field(default_factory=_now)
    last_seen_at: datetime = field(default_factory=_now)
    expires_at: Optional[datetime] = None
    revoked: bool = False

    def is_active(self) -> bool:
        if self.revoked:
            return False
        return self.expires_at is None or self.expires_at > _now()


class SessionStore(ABC):
    """Abstract store for active sessions."""

    @abstractmethod
    def create(
        self,
        session_id: str,
        user_id: str,
        device: str = "Unknown device",
        ip_address: str = "unknown",
    ) -> SessionRecord:
        """Record a new session."""

    @abstractmethod
    def get(self, session_id: str) -> Optional[SessionRecord]:
        """Return the session, or None if unknown."""

    @abstractmethod
    def list_for_user(self, user_id: str) -> List[SessionRecord]:
        """Return the user's active sessions, most recently seen first."""

    @abstractmethod
    def touch(self, session_id: str) -> None:
        """Update the session's last-seen timestamp."""

    @abstractmethod
    def revoke(self, session_id: str) -> bool:
        """Revoke one session. Returns True if it existed and was active."""

    @abstractmethod
    def revoke_all_for_user(self, user_id: str, except_session: Optional[str] = None) -> int:
        """Revoke every session for *user_id*, returning how many were revoked."""


class InMemorySessionStore(SessionStore):
    """Thread-safe in-process session store for tests and local dev."""

    def __init__(self, ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._lock = threading.RLock()
        self._sessions: Dict[str, SessionRecord] = {}

    def _purge_expired(self) -> None:
        """Caller must hold self._lock."""
        for key in [k for k, s in self._sessions.items() if not s.is_active()]:
            del self._sessions[key]

    def create(
        self,
        session_id: str,
        user_id: str,
        device: str = "Unknown device",
        ip_address: str = "unknown",
    ) -> SessionRecord:
        record = SessionRecord(
            session_id=session_id,
            user_id=user_id,
            device=device or "Unknown device",
            ip_address=ip_address or "unknown",
            expires_at=_now() + timedelta(seconds=self._ttl_seconds),
        )
        with self._lock:
            self._purge_expired()
            self._sessions[session_id] = record
        return record

    def get(self, session_id: str) -> Optional[SessionRecord]:
        with self._lock:
            record = self._sessions.get(session_id)
            return record if record and record.is_active() else None

    def list_for_user(self, user_id: str) -> List[SessionRecord]:
        with self._lock:
            self._purge_expired()
            sessions = [
                s for s in self._sessions.values()
                if s.user_id == user_id and s.is_active()
            ]
        return sorted(sessions, key=lambda s: s.last_seen_at, reverse=True)

    def touch(self, session_id: str) -> None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is not None and record.is_active():
                record.last_seen_at = _now()

    def revoke(self, session_id: str) -> bool:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None or not record.is_active():
                return False
            record.revoked = True
            return True

    def revoke_all_for_user(self, user_id: str, except_session: Optional[str] = None) -> int:
        revoked = 0
        with self._lock:
            for record in self._sessions.values():
                if record.user_id != user_id or not record.is_active():
                    continue
                if except_session and record.session_id == except_session:
                    continue
                record.revoked = True
                revoked += 1
        return revoked


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


@dataclass
class APIKeyRecord:
    """A issued API key. The raw key is never stored — only its hash."""

    key_id: str
    key_hash: str
    key_prefix: str
    name: str
    organization_id: str
    user_id: str
    scopes: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=_now)
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    revoked: bool = False

    def is_active(self) -> bool:
        if self.revoked:
            return False
        return self.expires_at is None or self.expires_at > _now()


class APIKeyStore(ABC):
    """Abstract store resolving a presented API key to its record."""

    @abstractmethod
    def create(
        self,
        name: str,
        organization_id: str,
        user_id: str,
        scopes: Optional[List[str]] = None,
        expires_at: Optional[datetime] = None,
    ) -> tuple[str, APIKeyRecord]:
        """Create a key, returning ``(raw_key, record)``.

        The raw key is returned exactly once and cannot be recovered later.
        """

    @abstractmethod
    def resolve(self, raw_key: str) -> Optional[APIKeyRecord]:
        """Return the active record for *raw_key*, or None."""

    @abstractmethod
    def list_for_organization(self, organization_id: str) -> List[APIKeyRecord]:
        """Return the organization's keys, newest first."""

    @abstractmethod
    def revoke(self, key_id: str, organization_id: str) -> bool:
        """Revoke a key owned by *organization_id*."""


class InMemoryAPIKeyStore(APIKeyStore):
    """Thread-safe in-process API key store for tests and local dev."""

    KEY_PREFIX = "sk_"

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_id: Dict[str, APIKeyRecord] = {}
        self._by_hash: Dict[str, str] = {}  # key_hash -> key_id

    def create(
        self,
        name: str,
        organization_id: str,
        user_id: str,
        scopes: Optional[List[str]] = None,
        expires_at: Optional[datetime] = None,
    ) -> tuple[str, APIKeyRecord]:
        raw_key = f"{self.KEY_PREFIX}{secrets.token_hex(32)}"
        key_hash = _hash(raw_key)
        record = APIKeyRecord(
            key_id=f"key_{secrets.token_hex(8)}",
            key_hash=key_hash,
            key_prefix=raw_key[:11],
            name=name,
            organization_id=organization_id,
            user_id=user_id,
            scopes=list(scopes or []),
            expires_at=expires_at,
        )
        with self._lock:
            self._by_id[record.key_id] = record
            self._by_hash[key_hash] = record.key_id
        return raw_key, record

    def resolve(self, raw_key: str) -> Optional[APIKeyRecord]:
        if not raw_key:
            return None
        key_hash = _hash(raw_key)
        with self._lock:
            key_id = self._by_hash.get(key_hash)
            if key_id is None:
                return None
            record = self._by_id.get(key_id)
            if record is None or not record.is_active():
                return None
            if not secrets.compare_digest(record.key_hash, key_hash):
                return None  # pragma: no cover - dict lookup already matched
            record.last_used_at = _now()
            return record

    def list_for_organization(self, organization_id: str) -> List[APIKeyRecord]:
        with self._lock:
            records = [
                r for r in self._by_id.values()
                if r.organization_id == organization_id and not r.revoked
            ]
        return sorted(records, key=lambda r: r.created_at, reverse=True)

    def revoke(self, key_id: str, organization_id: str) -> bool:
        with self._lock:
            record = self._by_id.get(key_id)
            # Ownership is checked here rather than in the route so no caller
            # can revoke another organization's key by guessing an id.
            if record is None or record.organization_id != organization_id:
                return False
            if record.revoked:
                return False
            record.revoked = True
            return True


# ---------------------------------------------------------------------------
# Notification dispatch
# ---------------------------------------------------------------------------


class NotificationSender(ABC):
    """Abstract outbound notification channel."""

    @abstractmethod
    def send_password_reset(self, email: str, token: str) -> None:
        """Deliver a password-reset token to *email*."""


class LoggingNotificationSender(NotificationSender):
    """Default sender that logs instead of delivering.

    Keeps the reset flow complete and testable without binding the project to
    an SMTP provider.  The token itself is never logged — only the fact that a
    reset was dispatched — so log access does not become account takeover.
    """

    def send_password_reset(self, email: str, token: str) -> None:
        logger.info(
            "Password reset dispatched for %s (token withheld from logs)", email
        )
