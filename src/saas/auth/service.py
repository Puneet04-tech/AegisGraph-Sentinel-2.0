"""
Enterprise Authentication Service
AegisGraph Sentinel Enterprise
Supports: SSO, SAML 2.0, OAuth2, OpenID Connect, MFA
"""

import hashlib
import logging
import os
import secrets
import pyotp
import bcrypt
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import jwt
from pydantic import BaseModel, EmailStr

from src.exceptions import AuthenticationError, AuthorizationError
from src.saas.auth.credential_stores import (
    APIKeyStore,
    InMemoryAPIKeyStore,
    InMemoryPasswordResetTokenStore,
    InMemorySessionStore,
    LoggingNotificationSender,
    NotificationSender,
    PasswordResetTokenStore,
    SessionStore,
)
from src.saas.auth.password_policy import enforce_password_policy

logger = logging.getLogger(__name__)


@dataclass
class UserRecord:
    """Minimal user record used by AuthService for authentication."""
    user_id: str
    organization_id: str
    email: str
    username: str = ""
    password_hash: str = ""
    mfa_enabled: bool = False
    mfa_secret: str = ""
    role: str = "member"
    permissions: List[str] = field(default_factory=lambda: ["read", "write"])


class UserStore(ABC):
    """Abstract user store interface.

    Concrete implementations back this with a database (PostgreSQL, DynamoDB,
    etc.).  An in-memory implementation (``InMemoryUserStore``) is provided for
    unit testing and local development.
    """

    @abstractmethod
    def get_by_id(self, user_id: str) -> Optional[UserRecord]:
        """Return the UserRecord for *user_id*, or None if not found."""

    @abstractmethod
    def get_by_email(self, email: str) -> Optional[UserRecord]:
        """Return the UserRecord for *email*, or None if not found."""

    @abstractmethod
    def find_or_create_sso_user(
        self, provider: str, user_info: Dict[str, Any]
    ) -> Tuple[str, str]:
        """Return (user_id, organization_id) for an SSO login, creating the
        user if this is their first sign-in."""

    # Write paths. The store originally exposed reads only, which is why
    # password change and MFA enrolment had nowhere to persist to. These raise
    # by default so a third-party store missing them fails loudly rather than
    # silently discarding a credential change.

    def update_password_hash(self, user_id: str, password_hash: str) -> None:
        """Persist a new password hash for *user_id*."""
        raise NotImplementedError(
            f"{type(self).__name__} does not support password updates"
        )

    def set_mfa(
        self, user_id: str, enabled: bool, secret: str = ""
    ) -> None:
        """Enable or disable MFA for *user_id*."""
        raise NotImplementedError(
            f"{type(self).__name__} does not support MFA updates"
        )

    def set_backup_codes(self, user_id: str, code_hashes: List[str]) -> None:
        """Replace the user's MFA backup codes (stored hashed)."""
        raise NotImplementedError(
            f"{type(self).__name__} does not support backup codes"
        )

    def consume_backup_code(self, user_id: str, code: str) -> bool:
        """Single-use-consume an MFA backup code."""
        raise NotImplementedError(
            f"{type(self).__name__} does not support backup codes"
        )

    def update_last_login(self, user_id: str) -> None:
        """Record a successful sign-in timestamp."""
        raise NotImplementedError(
            f"{type(self).__name__} does not support login tracking"
        )


class InMemoryUserStore(UserStore):
    """Thread-unsafe in-memory user store for development and testing only.

    Do **not** use this in production — records are not persisted across
    restarts and there is no concurrency protection.
    """

    def __init__(self) -> None:
        self._users: Dict[str, UserRecord] = {}
        self._email_index: Dict[str, str] = {}
        self._backup_codes: Dict[str, List[str]] = {}
        self._last_login: Dict[str, datetime] = {}

    def add(self, record: UserRecord) -> None:
        self._users[record.user_id] = record
        self._email_index[record.email] = record.user_id

    def update_password_hash(self, user_id: str, password_hash: str) -> None:
        record = self._users.get(user_id)
        if record is None:
            raise KeyError(f"Unknown user: {user_id}")
        record.password_hash = password_hash

    def set_mfa(self, user_id: str, enabled: bool, secret: str = "") -> None:
        record = self._users.get(user_id)
        if record is None:
            raise KeyError(f"Unknown user: {user_id}")
        record.mfa_enabled = enabled
        record.mfa_secret = secret if enabled else ""
        if not enabled:
            self._backup_codes.pop(user_id, None)

    def set_backup_codes(self, user_id: str, code_hashes: List[str]) -> None:
        if user_id not in self._users:
            raise KeyError(f"Unknown user: {user_id}")
        self._backup_codes[user_id] = list(code_hashes)

    def consume_backup_code(self, user_id: str, code: str) -> bool:
        stored = self._backup_codes.get(user_id)
        if not stored:
            return False
        candidate = hashlib.sha256(code.encode("utf-8")).hexdigest()
        for index, code_hash in enumerate(stored):
            if secrets.compare_digest(code_hash, candidate):
                # Single-use: a backup code cannot be replayed.
                del stored[index]
                return True
        return False

    def update_last_login(self, user_id: str) -> None:
        if user_id in self._users:
            self._last_login[user_id] = datetime.now(timezone.utc)

    def get_by_id(self, user_id: str) -> Optional[UserRecord]:
        return self._users.get(user_id)

    def get_by_email(self, email: str) -> Optional[UserRecord]:
        uid = self._email_index.get(email)
        return self._users.get(uid) if uid else None

    def find_or_create_sso_user(
        self, provider: str, user_info: Dict[str, Any]
    ) -> Tuple[str, str]:
        email = user_info.get("email", "")
        record = self.get_by_email(email)
        if record:
            return record.user_id, record.organization_id
        new_id = secrets.token_hex(8)
        new_org = secrets.token_hex(8)
        self.add(UserRecord(user_id=new_id, organization_id=new_org, email=email))
        return new_id, new_org
    
class MFAPendingStore(ABC):
    """Abstract store for pending-MFA session tokens.

    When a user passes the password step but has MFA enabled, the server
    issues a short-lived, single-use token recording "password verified,
    MFA pending". ``/mfa/verify`` must validate this token before checking
    the TOTP code, binding the second factor to a completed first factor.

    Concrete implementations would back this with Redis or a database that
    supports TTL. An in-memory implementation is provided for unit testing
    and local development.
    """

    @abstractmethod
    def issue(self, user_id: str) -> str:
        """Generate, store, and return a new pending-MFA token for *user_id*."""

    @abstractmethod
    def consume(self, user_id: str, mfa_token: str) -> bool:
        """Validate and single-use-consume a pending-MFA token.

        Return True iff a token exists for *user_id*, matches *mfa_token*,
        and has not expired. The entry is removed on any attempt (single-use),
        so a wrong or expired token cannot be retried.
        """
        
class InMemoryMFAPendingStore(MFAPendingStore):
    """Thread-unsafe in-memory pending-MFA store for development and testing.

    Do **not** use in production — tokens are not persisted across restarts
    and there is no concurrency protection.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._ttl_seconds = ttl_seconds
        # user_id -> (mfa_token, expires_at)
        self._pending: Dict[str, Tuple[str, datetime]] = {}

    def issue(self, user_id: str) -> str:
        mfa_token = secrets.token_hex(16)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._ttl_seconds)
        self._pending[user_id] = (mfa_token, expires_at)
        return mfa_token

    def consume(self, user_id: str, mfa_token: str) -> bool:
        entry = self._pending.pop(user_id, None)
        if entry is None:
            return False
        stored_token, expires_at = entry
        if datetime.now(timezone.utc) > expires_at:
            return False
        return secrets.compare_digest(stored_token, mfa_token)
    
class AuthProvider(str, Enum):
    """Supported authentication providers"""
    LOCAL = "local"
    GOOGLE = "google"
    MICROSOFT = "microsoft"
    OKTA = "okta"
    AZURE_AD = "azure_ad"
    SAML = "saml"
    API_KEY = "api_key"
    
class AuthMethod(str, Enum):
    """Authentication methods"""
    PASSWORD = "password"
    SSO = "sso"
    MFA_TOTP = "mfa_totp"
    MFA_SMS = "mfa_sms"
    API_KEY = "api_key"
    JWT = "jwt"


@dataclass
class AuthResult:
    """Authentication result"""
    success: bool
    user_id: Optional[str] = None
    email: Optional[str] = None
    organization_id: Optional[str] = None
    role: Optional[str] = None
    session_id: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None
    error: Optional[str] = None
    provider: Optional[AuthProvider] = None


@dataclass
class TokenPayload:
    """JWT token payload"""
    sub: str  # User ID
    org: str  # Organization ID
    email: str
    role: str
    permissions: List[str]
    exp: datetime
    iat: datetime
    jti: str  # JWT ID for revocation


class AuthService:
    """Enterprise authentication service"""

    def __init__(
        self,
        config: Dict[str, Any],
        user_store: Optional[UserStore] = None,
        mfa_pending_store: Optional["MFAPendingStore"] = None,
        reset_token_store: Optional[PasswordResetTokenStore] = None,
        session_store: Optional[SessionStore] = None,
        api_key_store: Optional[APIKeyStore] = None,
        notification_sender: Optional[NotificationSender] = None,
    ):
        self.config = config
        # Require an explicit secret in production; generate a random one only
        # as a last-resort fallback so tests without config don't crash.
        jwt_secret = config.get("jwt_secret") or os.getenv("AEGIS_JWT_SECRET")
        if not jwt_secret:
            logger.warning(
                "No jwt_secret configured — generating a random secret. "
                "Tokens will be invalid after restart. "
                "Set AEGIS_JWT_SECRET in production."
            )
            jwt_secret = secrets.token_hex(32)
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = "HS256"
        self.access_token_expiry = config.get("access_token_expiry", 3600)  # 1 hour
        self.refresh_token_expiry = config.get("refresh_token_expiry", 86400 * 7)  # 7 days

        self.user_store: UserStore = user_store or InMemoryUserStore()
        self.mfa_pending_store: MFAPendingStore = (
            mfa_pending_store or InMemoryMFAPendingStore()
        )
        self.revoked_token_ids: set[str] = set()
        # Secrets generated by begin_mfa_enrolment() but not yet confirmed with
        # a valid TOTP code. Held here rather than on the user record so an
        # abandoned enrolment never enables MFA.
        self._pending_mfa_secrets: Dict[str, str] = {}
        self.reset_token_store: PasswordResetTokenStore = (
            reset_token_store or InMemoryPasswordResetTokenStore()
        )
        self.session_store: SessionStore = session_store or InMemorySessionStore()
        self.api_key_store: APIKeyStore = api_key_store or InMemoryAPIKeyStore()
        self.notification_sender: NotificationSender = (
            notification_sender or LoggingNotificationSender()
        )
        self._runtime_credentials = self._load_runtime_credentials(config)
        self._credentials_configured = bool(self._runtime_credentials)

        # SSO providers
        self.sso_providers: Dict[str, 'SSOProvider'] = {}

    def _load_runtime_credentials(self, config: Dict[str, Any]) -> Dict[str, UserRecord]:
        """Load configured operator/admin identities from secure runtime config.

        Preference order:
        1. Streamlit secrets
        2. Environment variables
        3. Explicit runtime config dictionary

        Only password hashes are accepted. Missing or malformed credentials
        are ignored so the service can fail closed instead of creating a
        default backdoor.
        """
        sources: List[Dict[str, Any]] = []

        secrets_obj = self._load_streamlit_secrets()
        if secrets_obj:
            sources.append(secrets_obj)
        sources.append(os.environ)
        sources.append(config)

        credentials: Dict[str, UserRecord] = {}
        for role, default_org in (("admin", "administration"), ("operator", "operations")):
            username = self._read_credential_value(sources, f"{role.upper()}_USERNAME")
            password_hash = self._read_credential_value(sources, f"{role.upper()}_PASSWORD_HASH")
            if not username or not password_hash:
                continue
            if not self._is_supported_password_hash(password_hash):
                logger.warning("Ignoring %s credential with unsupported password hash format", role)
                continue

            record = UserRecord(
                user_id=f"{role}_user",
                organization_id=default_org,
                email=username,
                username=username,
                password_hash=password_hash,
                role=role,
                permissions=["read", "write", "admin"] if role == "admin" else ["read", "write"],
            )
            credentials[username.casefold()] = record
            credentials[username.strip().casefold()] = record
        return credentials

    @staticmethod
    def _load_streamlit_secrets() -> Dict[str, Any]:
        try:
            import streamlit as st  # type: ignore
        except Exception:
            return {}

        try:
            return dict(getattr(st, "secrets", {}) or {})
        except Exception:
            return {}

    @staticmethod
    def _read_credential_value(sources: List[Dict[str, Any]], key: str) -> Optional[str]:
        for source in sources:
            if key in source and source[key]:
                return str(source[key]).strip()
            lower_key = key.lower()
            if lower_key in source and source[lower_key]:
                return str(source[lower_key]).strip()
        return None

    @staticmethod
    def _is_supported_password_hash(password_hash: str) -> bool:
        return password_hash.startswith(("$2a$", "$2b$", "$2y$"))

    def _lookup_runtime_user(self, identifier: str) -> Optional[UserRecord]:
        return self._runtime_credentials.get(identifier.strip().casefold())

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode(), password_hash.encode())

    def generate_mfa_secret(self) -> str:
        """Generate new MFA secret"""
        return pyotp.random_base32()

    def get_mfa_uri(self, secret: str, email: str) -> str:
        """Get MFA provisioning URI"""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name="AegisGraph Sentinel")

    def verify_mfa_token(self, secret: str, token: str, window: int = 1) -> bool:
        """Verify MFA token with window for clock drift"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)

    def generate_backup_codes(self, count: int = 8) -> List[str]:
        """Generate MFA backup codes"""
        return [secrets.token_hex(8) for _ in range(count)]

    def create_access_token(self, payload: TokenPayload) -> str:
        """Create JWT access token"""
        data = {
            "sub": payload.sub,
            "org": payload.org,
            "email": payload.email,
            "role": payload.role,
            "permissions": payload.permissions,
            "exp": payload.exp,
            "iat": payload.iat,
            "jti": payload.jti,
        }
        return jwt.encode(data, self.jwt_secret, algorithm=self.jwt_algorithm)

    def create_refresh_token(self, user_id: str, session_id: str) -> str:
        """Create refresh token"""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "session": session_id,
            "type": "refresh",
            "exp": now + timedelta(seconds=self.refresh_token_expiry),
            "iat": now,
            "jti": secrets.token_hex(16),
        }
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

    def verify_token(self, token: str) -> Optional[TokenPayload]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            if payload.get("jti") in self.revoked_token_ids:
                raise AuthenticationError("Token has been revoked")
            return TokenPayload(
                sub=payload["sub"],
                org=payload["org"],
                email=payload["email"],
                role=payload["role"],
                permissions=payload["permissions"],
                exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
                iat=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
                jti=payload["jti"],
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")

    def authenticate_user(
        self,
        email: str,
        password: str,
    ) -> AuthResult:
        """Authenticate user with email and password.

        Looks up the user via the injected ``UserStore``.  Returns an
        ``AuthResult`` with ``success=False`` when the user is not found or
        the password does not match.
        """
        record = self.user_store.get_by_email(email)
        if record is None:
            record = self._lookup_runtime_user(email)

        if record is None and not self._credentials_configured and not self._has_any_user_records():
            return AuthResult(success=False, error="Authentication is not configured")

        if record is None:
            return AuthResult(success=False, error="Invalid credentials")

        if record.password_hash:
            if not self.verify_password(password, record.password_hash):
                return AuthResult(success=False, error="Invalid credentials")
        else:
            return AuthResult(success=False, error="Authentication is not configured")

        if record.mfa_enabled:
            mfa_token = self.mfa_pending_store.issue(record.user_id)
            return AuthResult(
                success=True,
                user_id=record.user_id,
                organization_id=record.organization_id,
                mfa_required=True,
                mfa_token=mfa_token,
            )

        return self._create_auth_result(record)

    def _has_any_user_records(self) -> bool:
        if hasattr(self.user_store, "_users"):
            return bool(getattr(self.user_store, "_users", {}))
        return False

    def authenticate_api_key(self, api_key: str) -> AuthResult:
        """Authenticate using API key.

        Resolves the presented key through the injected ``APIKeyStore``, which
        indexes keys by SHA-256 hash.  Revoked and expired keys resolve to
        ``None`` and are refused.
        """
        if not api_key:
            return AuthResult(
                success=False,
                error="API key is required",
                provider=AuthProvider.API_KEY,
            )

        record = self.api_key_store.resolve(api_key)
        if record is None:
            # Deliberately uniform: a revoked key, an expired key, and a key
            # that never existed are indistinguishable to the caller.
            return AuthResult(
                success=False,
                error="Invalid API key",
                provider=AuthProvider.API_KEY,
            )

        return AuthResult(
            success=True,
            user_id=record.user_id,
            organization_id=record.organization_id,
            role="member",
            provider=AuthProvider.API_KEY,
        )

    def authenticate_sso(
        self,
        provider: AuthProvider,
        code: str,
        redirect_uri: str,
    ) -> AuthResult:
        """Authenticate using SSO provider"""
        if provider not in self.sso_providers:
            return AuthResult(
                success=False,
                error=f"Provider {provider} not configured",
            )

        sso_provider = self.sso_providers[provider]

        # Exchange code for tokens
        tokens = sso_provider.exchange_code(code, redirect_uri)

        # Get user info from provider
        user_info = sso_provider.get_user_info(tokens["access_token"])

        # Find or create user
        user_id, _ = self._find_or_create_sso_user(provider, user_info)

        record = self.user_store.get_by_id(user_id)
        if record is None:
            return AuthResult(success=False, error="User record not found after SSO login")

        return self._create_auth_result(record, provider=provider)

    def verify_mfa(self, user_id: str, mfa_token: str, token: str) -> AuthResult:
        """Verify TOTP MFA token and complete authentication.

        Fetches the per-user MFA secret from the ``UserStore``.  Returns
        ``success=False`` when the user is not found, MFA is not configured
        for the user, the pending-MFA session token is missing/expired, or the
        TOTP token is incorrect.
        """
        record = self.user_store.get_by_id(user_id)
        if record is None:
            return AuthResult(success=False, error="User not found")

        if not record.mfa_enabled or not record.mfa_secret:
            return AuthResult(success=False, error="MFA is not configured for this user")
        
        if not self.mfa_pending_store.consume(user_id, mfa_token):
            return AuthResult(
                success=False,
                error="Invalid or expired MFA session",
            )

        if not self.verify_mfa_token(record.mfa_secret, token):
            return AuthResult(success=False, error="Invalid MFA token")

        return self._create_auth_result(record)

    def _create_auth_result(
        self,
        record: UserRecord,
        provider: Optional[AuthProvider] = None,
        device: str = "Unknown device",
        ip_address: str = "unknown",
    ) -> AuthResult:
        """Create successful authentication result.

        The ``session_id`` minted here is now recorded in the ``SessionStore``,
        so ``GET /sessions`` reports real sign-ins rather than placeholders and
        ``DELETE /sessions/{id}`` has something to revoke.
        """
        session_id = secrets.token_hex(16)
        now = datetime.now(timezone.utc)

        try:
            self.session_store.create(
                session_id=session_id,
                user_id=record.user_id,
                device=device,
                ip_address=ip_address,
            )
            self.user_store.update_last_login(record.user_id)
        except NotImplementedError:
            # A third-party UserStore without login tracking must not prevent
            # sign-in; the session itself is still recorded above.
            logger.debug("User store does not support login tracking")
        except Exception as exc:
            logger.warning("Could not record session: %s", exc)

        access_payload = TokenPayload(
            sub=record.user_id,
            org=record.organization_id,
            email=record.email,
            role=record.role,
            permissions=record.permissions,
            exp=now + timedelta(seconds=self.access_token_expiry),
            iat=now,
            jti=secrets.token_hex(16),
        )

        access_token = self.create_access_token(access_payload)
        refresh_token = self.create_refresh_token(record.user_id, session_id)

        return AuthResult(
            success=True,
            user_id=record.user_id,
            email=record.email,
            organization_id=record.organization_id,
            role=record.role,
            session_id=session_id,
            access_token=access_token,
            refresh_token=refresh_token,
            provider=provider or AuthProvider.LOCAL,
        )

    def _find_or_create_sso_user(
        self,
        provider: AuthProvider,
        user_info: Dict[str, Any],
    ) -> Tuple[str, str]:
        """Find or create a user record for an SSO login via the UserStore."""
        return self.user_store.find_or_create_sso_user(provider.value, user_info)

    def refresh_tokens(self, refresh_token: str) -> AuthResult:
        """Issue a new access/refresh token pair from a valid refresh token.

        Decodes the supplied JWT, confirms it carries ``type == "refresh"``,
        then delegates to ``_create_auth_result`` to mint fresh tokens.
        Raises ``AuthenticationError`` on any validation failure so the caller
        can map it to an appropriate HTTP response.
        """
        try:
            payload = jwt.decode(
                refresh_token, self.jwt_secret, algorithms=[self.jwt_algorithm]
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Refresh token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid refresh token")

        if payload.get("type") != "refresh":
            raise AuthenticationError("Token is not a refresh token")

        user_id = payload.get("sub")
        if not user_id:
            raise AuthenticationError("Malformed refresh token: missing subject")

        record = self.user_store.get_by_id(user_id)
        if record is None:
            raise AuthenticationError("User not found")

        return self._create_auth_result(record)

    def revoke_token_id(self, token_id: str) -> None:
        if token_id:
            self.revoked_token_ids.add(token_id)

    # ------------------------------------------------------------------
    # Credential lifecycle
    # ------------------------------------------------------------------

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> None:
        """Verify the current password and persist a new one.

        Raises ``AuthenticationError`` when the current password is wrong and
        ``PasswordPolicyError`` when the new one fails the policy.  The caller
        is expected to revoke the user's other sessions afterwards — a password
        change is usually a response to suspected compromise, so leaving other
        devices signed in would defeat the point.
        """
        record = self.user_store.get_by_id(user_id)
        if record is None:
            raise AuthenticationError("User not found")
        if not record.password_hash:
            raise AuthenticationError("Password authentication is not configured")
        if not self.verify_password(current_password, record.password_hash):
            raise AuthenticationError("Current password is incorrect")

        enforce_password_policy(
            new_password, email=record.email, username=record.username
        )
        if self.verify_password(new_password, record.password_hash):
            raise AuthenticationError("New password must differ from the current one")

        self.user_store.update_password_hash(user_id, self.hash_password(new_password))

    def set_password(self, user_id: str, new_password: str) -> None:
        """Set a password without knowing the previous one.

        Used by the reset flow, where possession of a valid single-use token
        stands in for knowledge of the old password.
        """
        record = self.user_store.get_by_id(user_id)
        if record is None:
            raise AuthenticationError("User not found")
        enforce_password_policy(
            new_password, email=record.email, username=record.username
        )
        self.user_store.update_password_hash(user_id, self.hash_password(new_password))

    def begin_mfa_enrolment(self, user_id: str) -> Tuple[str, str, List[str]]:
        """Generate an MFA secret and backup codes without enabling MFA yet.

        Enrolment is two-phase deliberately: enabling on the first call would
        let a user who scans the QR code and navigates away lock themselves out
        of an account whose second factor they never confirmed.
        """
        record = self.user_store.get_by_id(user_id)
        if record is None:
            raise AuthenticationError("User not found")
        if record.mfa_enabled:
            raise AuthorizationError("MFA is already enabled for this account")

        secret = self.generate_mfa_secret()
        uri = self.get_mfa_uri(secret, record.email)
        backup_codes = self.generate_backup_codes()
        self._pending_mfa_secrets[user_id] = secret
        return secret, uri, backup_codes

    def complete_mfa_enrolment(
        self,
        user_id: str,
        totp_code: str,
        backup_codes: Optional[List[str]] = None,
    ) -> None:
        """Confirm enrolment with a valid TOTP code and enable MFA."""
        record = self.user_store.get_by_id(user_id)
        if record is None:
            raise AuthenticationError("User not found")

        secret = self._pending_mfa_secrets.get(user_id)
        if not secret:
            raise AuthenticationError("No pending MFA enrolment for this account")
        if not self.verify_mfa_token(secret, totp_code):
            raise AuthenticationError("Invalid MFA code")

        self.user_store.set_mfa(user_id, True, secret)
        if backup_codes:
            self.user_store.set_backup_codes(
                user_id,
                [hashlib.sha256(c.encode("utf-8")).hexdigest() for c in backup_codes],
            )
        self._pending_mfa_secrets.pop(user_id, None)

    def disable_mfa(self, user_id: str, current_password: str) -> None:
        """Disable MFA after verifying the account password.

        The password check is the point of this endpoint: without it, anyone
        holding a stolen access token could strip the second factor.
        """
        record = self.user_store.get_by_id(user_id)
        if record is None:
            raise AuthenticationError("User not found")
        if not record.password_hash:
            raise AuthenticationError("Password authentication is not configured")
        if not self.verify_password(current_password, record.password_hash):
            raise AuthenticationError("Current password is incorrect")
        if not record.mfa_enabled:
            raise AuthorizationError("MFA is not enabled for this account")

        self.user_store.set_mfa(user_id, False)
        self._pending_mfa_secrets.pop(user_id, None)

    def add_sso_provider(self, provider: AuthProvider, config: Dict[str, Any]):
        """Add SSO provider configuration"""
        if provider == AuthProvider.OKTA:
            self.sso_providers[provider] = OktaSSOProvider(config)
        elif provider == AuthProvider.AZURE_AD:
            self.sso_providers[provider] = AzureADSSOProvider(config)
        elif provider == AuthProvider.GOOGLE:
            self.sso_providers[provider] = GoogleSSOProvider(config)
        else:
            raise ValueError(f"Unsupported SSO provider: {provider}")


class SSOProvider:
    """Base SSO provider interface"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.redirect_uri = config.get("redirect_uri")

    def get_authorization_url(self) -> str:
        """Get OAuth authorization URL"""
        raise NotImplementedError

    def exchange_code(self, code: str, redirect_uri: str) -> Dict[str, str]:
        """Exchange authorization code for tokens"""
        raise NotImplementedError

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from provider"""
        raise NotImplementedError


class OktaSSOProvider(SSOProvider):
    """Okta SSO provider implementation"""

    def get_authorization_url(self) -> str:
        base_url = self.config.get("okta_domain", "https://your-domain.okta.com")
        return f"{base_url}/oauth2/v1/authorize?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code"

    def exchange_code(self, code: str, redirect_uri: str) -> Dict[str, str]:
        # In production, make API call to Okta
        return {"access_token": "mock_token", "id_token": "mock_id_token"}

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        # In production, decode ID token or call userinfo endpoint
        return {
            "sub": "user_id_from_okta",
            "email": "user@example.com",
            "name": "User Name",
        }


class AzureADSSOProvider(SSOProvider):
    """Azure AD SSO provider implementation"""

    def get_authorization_url(self) -> str:
        tenant = self.config.get("tenant_id")
        return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code"

    def exchange_code(self, code: str, redirect_uri: str) -> Dict[str, str]:
        return {"access_token": "mock_token", "id_token": "mock_id_token"}

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        return {
            "sub": "user_id_from_azure",
            "email": "user@example.com",
            "name": "User Name",
        }


class GoogleSSOProvider(SSOProvider):
    """Google SSO provider implementation"""

    def get_authorization_url(self) -> str:
        return f"https://accounts.google.com/o/oauth2/v2/auth?client_id={self.client_id}&redirect_uri={self.redirect_uri}&response_type=code&scope=openid%20email%20profile"

    def exchange_code(self, code: str, redirect_uri: str) -> Dict[str, str]:
        return {"access_token": "mock_token", "id_token": "mock_id_token"}

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        return {
            "sub": "user_id_from_google",
            "email": "user@example.com",
            "name": "User Name",
        }


# SAML Provider
class SAMLProvider:
    """SAML 2.0 provider implementation"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.idp_metadata_url = config.get("idp_metadata_url")
        self.sp_entity_id = config.get("sp_entity_id")
        self.acs_url = config.get("acs_url")
        self.certificate = config.get("certificate")
        self.private_key = config.get("private_key")

    def get_metadata(self) -> str:
        """Get SP metadata for IdP configuration"""
        return f"""<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{self.sp_entity_id}">
    <SPSSODescriptor AuthnRequestsSigned="true">
        <AssertionConsumerService 
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="{self.acs_url}" />
    </SPSSODescriptor>
</EntityDescriptor>"""

    def process_response(self, saml_response: str) -> Dict[str, Any]:
        """Process SAML response from IdP"""
        # In production, use python3-saml library
        # Verify signature, decrypt, and extract user info
        return {
            "name_id": "user@example.com",
            "attributes": {
                "email": "user@example.com",
                "firstName": "User",
                "lastName": "Name",
            }
        }


# RBAC Service
class RBACService:
    """Role-Based Access Control service"""

    # Default roles with permissions
    ROLES = {
        "owner": ["*"],
        "admin": [
            "users:read", "users:write", "users:delete",
            "workspace:read", "workspace:write", "workspace:delete",
            "billing:read", "billing:write",
            "settings:read", "settings:write",
            "api_keys:read", "api_keys:write", "api_keys:delete",
            "audit:read",
            "reports:read", "reports:write",
            "cases:read", "cases:write", "cases:delete",
        ],
        "member": [
            "workspace:read", "workspace:write",
            "api_keys:read",
            "cases:read", "cases:write",
            "reports:read",
        ],
        "viewer": [
            "workspace:read",
            "cases:read",
            "reports:read",
        ],
    }

    def __init__(self):
        self.custom_roles: Dict[str, List[str]] = {}

    def get_role_permissions(self, role: str) -> List[str]:
        """Get permissions for a role"""
        if role in self.ROLES:
            return self.ROLES[role]
        if role in self.custom_roles:
            return self.custom_roles[role]
        return []

    def has_permission(self, role: str, permission: str) -> bool:
        """Check if role has permission"""
        perms = self.get_role_permissions(role)
        if "*" in perms:
            return True
        return permission in perms

    def require_permission(self, role: str, permission: str):
        """Raise exception if permission denied"""
        if not self.has_permission(role, permission):
            raise AuthorizationError(f"Permission denied: {permission}")

    def create_custom_role(self, name: str, permissions: List[str]):
        """Create custom role"""
        self.custom_roles[name] = permissions

    def delete_custom_role(self, name: str):
        """Delete custom role"""
        if name in self.custom_roles:
            del self.custom_roles[name]


# ABAC Service
class ABACService:
    """Attribute-Based Access Control service"""

    def __init__(self):
        self.policies: List[Dict[str, Any]] = []

    def add_policy(self, policy: Dict[str, Any]):
        """Add access control policy"""
        self.policies.append(policy)

    def evaluate(
        self,
        subject: Dict[str, Any],  # User attributes
        resource: Dict[str, Any],  # Resource attributes
        action: str,  # Action being performed
        environment: Dict[str, Any],  # Context attributes
    ) -> bool:
        """Evaluate access control policy"""
        for policy in self.policies:
            if self._matches_policy(policy, subject, resource, action, environment):
                return policy.get("effect") == "allow"
        return True  # Default deny

    def _matches_policy(
        self,
        policy: Dict[str, Any],
        subject: Dict[str, Any],
        resource: Dict[str, Any],
        action: str,
        environment: Dict[str, Any],
    ) -> bool:
        """Check if policy matches the request"""
        # Check subjects
        if "subjects" in policy:
            if not self._matches_attributes(subject, policy["subjects"]):
                return False

        # Check resources
        if "resources" in policy:
            if not self._matches_attributes(resource, policy["resources"]):
                return False

        # Check actions
        if "actions" in policy:
            if action not in policy["actions"]:
                return False

        # Check environment
        if "environment" in policy:
            if not self._matches_attributes(environment, policy["environment"]):
                return False

        return True

    def _matches_attributes(
        self,
        attributes: Dict[str, Any],
        constraints: Dict[str, Any],
    ) -> bool:
        """Check if attributes match constraints"""
        for key, constraint in constraints.items():
            if key not in attributes:
                return False
            if isinstance(constraint, dict):
                # Operator-based constraint
                op = constraint.get("op", "eq")
                value = constraint.get("value")
                attr_value = attributes[key]
                
                if op == "eq" and attr_value != value:
                    return False
                elif op == "neq" and attr_value == value:
                    return False
                elif op == "gt" and not (attr_value > value):
                    return False
                elif op == "lt" and not (attr_value < value):
                    return False
                elif op == "in" and attr_value not in value:
                    return False
            else:
                # Direct match
                if attributes[key] != constraint:
                    return False
        return True


# Module-level service singletons.
# jwt_secret is read from AEGIS_JWT_SECRET at startup; AuthService will emit
# a warning and generate a random secret if the env var is not set.
auth_service = AuthService({
    "access_token_expiry": 3600,
    "refresh_token_expiry": 86400 * 7,
})

rbac_service = RBACService()
abac_service = ABACService()
