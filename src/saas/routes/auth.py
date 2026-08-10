"""
Authentication Routes
AegisGraph Sentinel Enterprise SaaS Platform
Supports: Email/Password, SSO, MFA, API Keys
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader, HTTPBearer, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field

from src.exceptions import AuthenticationError, AuthorizationError
from src.exceptions.error_responses import build_rate_limit_error_payload
from src.saas.auth.attempt_limiter import (
    AuthAttemptLimiter,
    build_attempt_limiter,
    SCOPE_ACCOUNT,
    SCOPE_PASSWORD_RESET,
    SCOPE_TOTP,
)
from src.saas.auth.password_policy import PasswordPolicyError
from src.saas.auth.revocation import TokenRevocationStore, build_revocation_store
from src.saas.auth.service import (
    ABACService,
    AuthProvider,
    AuthResult,
    AuthService,
    RBACService,
)

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])

# Security schemes
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

logger = logging.getLogger(__name__)

_AUTH_SERVICE: Optional[AuthService] = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., description="A valid refresh token issued by a previous login")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, description="Username or email")
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    user: dict
    organization: dict


class MFAEnrollmentResponse(BaseModel):
    secret: str
    uri: str
    backup_codes: List[str]


class MFATokenRequest(BaseModel):
    user_id: str
    mfa_token: str
    totp_code: str


class SSOProviderRequest(BaseModel):
    provider: AuthProvider
    redirect_uri: Optional[str] = None


class SSOCallbackRequest(BaseModel):
    code: str
    state: str
    provider: AuthProvider


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class MFAConfirmRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=10)


class MFADisableRequest(BaseModel):
    current_password: str


class SessionResponse(BaseModel):
    id: str
    device: str
    ip_address: str
    created_at: datetime
    last_active: datetime
    current: bool


class APIKeyCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    scopes: List[str] = []
    expires_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    id: str
    name: str
    key: str
    key_prefix: str
    scopes: List[str]
    expires_at: Optional[datetime]
    created_at: datetime


def _load_jwt_secret() -> str:
    """Return the configured JWT secret from the project's settings system."""
    from src.config.settings import get_settings

    secret = get_settings().secret_key.strip()
    if not secret:
        raise RuntimeError("SECRET_KEY is not configured.")
    return secret


def _register_configured_sso_providers(service: AuthService) -> None:
    """Register SSO providers from environment configuration."""
    sso_providers = {
        AuthProvider.GOOGLE: {
            "client_id": os.getenv("OAUTH_GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("OAUTH_GOOGLE_CLIENT_SECRET"),
        },
        AuthProvider.OKTA: {
            "client_id": os.getenv("OAUTH_OKTA_CLIENT_ID"),
            "client_secret": os.getenv("OAUTH_OKTA_CLIENT_SECRET"),
            "okta_domain": os.getenv("OAUTH_OKTA_DOMAIN", ""),
        },
        AuthProvider.AZURE_AD: {
            "client_id": os.getenv("OAUTH_AZURE_CLIENT_ID"),
            "client_secret": os.getenv("OAUTH_AZURE_CLIENT_SECRET"),
            "tenant_id": os.getenv("OAUTH_AZURE_TENANT_ID", "common"),
        },
    }

    for provider, cfg in sso_providers.items():
        if cfg.get("client_id") and cfg.get("client_secret"):
            try:
                service.add_sso_provider(provider, cfg)
                logger.info("SSO provider registered: %s", provider.value)
            except Exception as exc:
                logger.warning("Failed to register SSO provider %s: %s", provider.value, exc)
        else:
            logger.debug("SSO provider %s not configured (missing env vars)", provider.value)


def _build_attempt_limiter() -> AuthAttemptLimiter:
    """Build the limiter named by ``AEGIS_AUTH_LIMITER_BACKEND``.

    Defaults to in-memory so local development and the test suite need no
    external service. Multi-worker deployments must set this to ``redis``,
    otherwise each worker enforces the threshold independently and the
    effective budget is multiplied by the worker count.
    """
    from src.config.settings import get_settings

    backend = os.getenv("AEGIS_AUTH_LIMITER_BACKEND", "memory")
    redis_url = None
    if backend.strip().lower() == "redis":
        try:
            redis_url = get_settings().innovations.redis_url
        except Exception as exc:
            logger.warning("Could not read Redis URL from settings: %s", exc)
    return build_attempt_limiter(backend, redis_url)


def _build_revocation_store() -> TokenRevocationStore:
    """Build the revocation store named by ``AEGIS_REVOCATION_BACKEND``.

    Defaults to in-memory for local development. Multi-worker deployments must
    set this to ``redis``, otherwise a logout handled by one worker is
    invisible to the others and the revoked token stays live on every process
    that did not see it.
    """
    from src.config.settings import get_settings

    backend = os.getenv("AEGIS_REVOCATION_BACKEND", "memory")
    redis_url = None
    if backend.strip().lower() == "redis":
        try:
            redis_url = get_settings().innovations.redis_url
        except Exception as exc:
            logger.warning("Could not read Redis URL from settings: %s", exc)
    return build_revocation_store(backend, redis_url)


def _build_auth_service() -> AuthService:
    try:
        jwt_secret = _load_jwt_secret()
    except Exception as exc:
        raise RuntimeError("SECRET_KEY is not configured.") from exc

    service = AuthService(
        {
            "jwt_secret": jwt_secret,
            "access_token_expiry": 3600,
            "refresh_token_expiry": 86400 * 7,
        },
        attempt_limiter=_build_attempt_limiter(),
        revocation_store=_build_revocation_store(),
    )
    _register_configured_sso_providers(service)
    return service


def _get_auth_service() -> AuthService:
    global _AUTH_SERVICE
    if _AUTH_SERVICE is None:
        _AUTH_SERVICE = _build_auth_service()
    return _AUTH_SERVICE


class _AuthServiceProxy:
    def __getattr__(self, item: str) -> Any:
        return getattr(_get_auth_service(), item)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} for AuthService>"


# Backup codes shown at enrolment, held until the user confirms with a TOTP
# code. Dropped on confirmation so the plaintext does not linger.
_pending_backup_codes: dict[str, List[str]] = {}

auth_service = _AuthServiceProxy()
rbac_service = RBACService()
abac_service = ABACService()

# Allow-list of permitted redirect URIs for SSO flows.
_SSO_REDIRECT_ALLOWLIST: List[str] = [
    uri.strip()
    for uri in os.getenv("OAUTH_REDIRECT_URIS", "").split(",")
    if uri.strip()
]


class InMemorySSOStateStore:
    """Short-TTL, single-use OAuth ``state`` values bound to an SSO provider.

    Mirrors the MFA pending-token pattern: authorize mints a value, callback
    must present the same value for the same provider, and the entry is
    consumed so it cannot be replayed. Fail closed on missing/mismatched/
    expired state.

    The state also carries the exact ``redirect_uri`` used to build the
    authorization URL, so the callback can echo it in the token exchange
    (RFC 6749 requires the exchange URI to match the authorization URI).
    """

    def __init__(self, ttl_seconds: int = 600) -> None:
        self._ttl_seconds = ttl_seconds
        # state -> (provider, redirect_uri, expires_at)
        self._pending: dict[str, tuple[str, str, datetime]] = {}

    def issue(self, provider: str, redirect_uri: str = "") -> str:
        state = secrets.token_urlsafe(24)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._ttl_seconds)
        self._pending[state] = (provider, redirect_uri, expires_at)
        return state

    def consume(self, state: str, provider: str) -> Optional[str]:
        """Consume a state and return its bound redirect_uri, or ``None``.

        Returns ``None`` for empty input, unknown/expired state, or a provider
        mismatch. A legitimate entry with no redirect_uri bound returns ``""``.
        """
        if not state or not provider:
            return None
        entry = self._pending.pop(state, None)
        if entry is None:
            return None
        stored_provider, stored_redirect_uri, expires_at = entry
        if datetime.now(timezone.utc) > expires_at:
            return None
        if not secrets.compare_digest(stored_provider, provider):
            return None
        return stored_redirect_uri


# Module-level store for SSO CSRF state. Tests may replace this instance.
_sso_state_store = InMemorySSOStateStore()


def _client_ip(request: Optional[Request]) -> Optional[str]:
    """Resolve the caller's address for the per-address lockout budget.

    Uses the project's proxy-aware resolver rather than reading headers
    directly, so a spoofed ``X-Forwarded-For`` cannot be used to dodge the
    budget or to lock out somebody else's address. Returns ``None`` when the
    address cannot be determined; the per-account budget still applies.
    """
    if request is None:
        return None
    try:
        from src.api.dependencies.ip_resolution import get_remote_address

        return get_remote_address(request)
    except Exception as exc:
        logger.warning("Could not resolve client address for rate limiting: %s", exc)
        return None


def _raise_if_rate_limited(result: AuthResult) -> None:
    """Translate a lockout refusal into 429 with ``Retry-After``.

    Kept separate from the 401 path so the two are never conflated: a client
    must be able to tell "wrong password" from "stop trying for a while".
    """
    if not result.rate_limited:
        return
    retry_after = max(1, result.retry_after_seconds)
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=build_rate_limit_error_payload(
            retry_after_seconds=retry_after,
            limit_type="authentication",
        ),
        headers={"Retry-After": str(retry_after)},
    )


async def get_current_user(authorization: Optional[str] = Depends(bearer_scheme)):
    """Get current authenticated user"""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    token = authorization.credentials
    try:
        payload = _get_auth_service().verify_token(token)
        return {
            "user_id": payload.sub,
            "organization_id": payload.org,
            "email": payload.email,
            "role": payload.role,
            "jti": payload.jti,
            "sid": payload.sid,
            "exp": payload.exp,
        }
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired credentials",
        )


async def get_optional_user(authorization: Optional[str] = Depends(bearer_scheme)):
    """Get current user if authenticated, None otherwise"""
    if not authorization:
        return None

    try:
        return await get_current_user(authorization)
    except HTTPException:
        return None
    except Exception as exc:
        logging.getLogger(__name__).warning(
            "Unexpected error during optional user authentication: %s", exc
        )
        return None


async def verify_api_key(api_key: Optional[str] = Depends(api_key_header)):
    """Verify API key authentication"""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )

    result = _get_auth_service().authenticate_api_key(api_key)
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error or "Invalid API key",
        )

    return {
        "organization_id": result.organization_id,
        "auth_method": "api_key",
    }


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, http_request: Request):
    """Login with username and password."""
    result = _get_auth_service().authenticate_user(
        email=request.username,
        password=request.password,
        ip_address=_client_ip(http_request),
    )

    if not result.success:
        _raise_if_rate_limited(result)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error or "Authentication failed",
        )

    if result.mfa_required:
        return LoginResponse(
            access_token="",
            refresh_token="",
            expires_in=0,
            user={"mfa_required": True, "mfa_token": result.mfa_token},
            organization={},
        )

    return LoginResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=3600,
        role=result.role or "member",
        user={
            "id": result.user_id,
            "email": result.email or request.username,
            "username": request.username,
        },
        organization={"id": result.organization_id},
    )


@router.post("/mfa/verify")
async def verify_mfa(request: MFATokenRequest):
    """Verify MFA token and complete login"""
    result = _get_auth_service().verify_mfa(
        user_id=request.user_id,
        mfa_token=request.mfa_token,
        token=request.totp_code,
    )

    if not result.success:
        _raise_if_rate_limited(result)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token",
        )

    return LoginResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=3600,
        role=result.role or "member",
        user={"id": result.user_id},
        organization={"id": result.organization_id},
    )


@router.post("/mfa/enroll", response_model=MFAEnrollmentResponse)
async def enroll_mfa(current_user: dict = Depends(get_current_user)):
    """Begin MFA enrolment.

    The secret is held pending until confirmed via ``/mfa/enroll/confirm``.
    Enabling here would let a user who scans the QR code and navigates away
    lock themselves out of an account whose second factor they never proved
    they hold.
    """
    try:
        secret, uri, backup_codes = _get_auth_service().begin_mfa_enrolment(
            current_user["user_id"]
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))

    _pending_backup_codes[current_user["user_id"]] = backup_codes
    return MFAEnrollmentResponse(secret=secret, uri=uri, backup_codes=backup_codes)


@router.post("/mfa/enroll/confirm")
async def confirm_mfa_enrollment(
    request: MFAConfirmRequest,
    current_user: dict = Depends(get_current_user),
):
    """Confirm MFA enrolment with a code from the authenticator app."""
    user_id = current_user["user_id"]
    try:
        _get_auth_service().complete_mfa_enrolment(
            user_id,
            request.totp_code,
            backup_codes=_pending_backup_codes.pop(user_id, None),
        )
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))

    return {"success": True, "message": "MFA enabled", "mfa_enabled": True}


@router.post("/mfa/disable")
async def disable_mfa(
    request: MFADisableRequest,
    current_user: dict = Depends(get_current_user),
):
    """Disable MFA after verifying the account password.

    The password check is the whole point of this endpoint: without it, anyone
    holding a stolen access token could strip the second factor.
    """
    try:
        _get_auth_service().disable_mfa(
            current_user["user_id"], request.current_password
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))

    return {"success": True, "message": "MFA disabled", "mfa_enabled": False}


@router.get("/sso/providers")
async def list_sso_providers():
    """List available SSO providers"""
    return {
        "providers": [
            {"id": "google", "name": "Google", "icon": "google_icon_url", "enabled": True},
            {"id": "microsoft", "name": "Microsoft", "icon": "microsoft_icon_url", "enabled": True},
            {"id": "okta", "name": "Okta", "icon": "okta_icon_url", "enabled": True},
            {"id": "azure_ad", "name": "Azure AD", "icon": "azure_icon_url", "enabled": True},
        ]
    }


@router.get("/sso/{provider}/authorize")
async def sso_authorize(
    provider: AuthProvider,
    redirect_uri: str,
    current_user: dict = Depends(get_current_user),
):
    """Initiate SSO authorization."""
    # Fail closed: with no configured allowlist, SSO authorization is disabled
    # rather than accepting arbitrary redirect targets.
    if not _SSO_REDIRECT_ALLOWLIST:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "SSO authorization is disabled: set the OAUTH_REDIRECT_URIS "
                "environment variable before enabling SSO"
            ),
        )

    if redirect_uri not in _SSO_REDIRECT_ALLOWLIST:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="redirect_uri is not in the configured allow-list",
        )

    sso_provider = _get_auth_service().sso_providers.get(provider)
    if not sso_provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"SSO provider '{provider.value}' is not configured. "
                f"Set OAUTH_{provider.value.upper()}_CLIENT_ID and "
                f"OAUTH_{provider.value.upper()}_CLIENT_SECRET environment variables."
            ),
        )

    sso_provider.redirect_uri = redirect_uri
    state = _sso_state_store.issue(provider.value, redirect_uri)
    authorization_url = sso_provider.get_authorization_url()
    separator = "&" if "?" in authorization_url else "?"
    authorization_url = f"{authorization_url}{separator}state={state}"
    return {"authorization_url": authorization_url, "state": state}


@router.post("/sso/callback", response_model=LoginResponse)
async def sso_callback(request: SSOCallbackRequest):
    """Handle SSO callback"""
    redirect_uri = _sso_state_store.consume(request.state, request.provider.value)
    if redirect_uri is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired SSO state",
        )

    result = _get_auth_service().authenticate_sso(
        provider=request.provider,
        code=request.code,
        redirect_uri=redirect_uri,
    )

    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error or "SSO authentication failed",
        )

    return LoginResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=3600,
        role=result.role or "member",
        user={"id": result.user_id},
        organization={"id": result.organization_id},
    )


@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(body: RefreshTokenRequest):
    """Exchange a valid refresh token for a new access/refresh token pair."""
    try:
        result = _get_auth_service().refresh_tokens(body.refresh_token)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )

    return LoginResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=_get_auth_service().access_token_expiry,
        role=result.role or "member",
        user={"id": result.user_id},
        organization={"id": result.organization_id},
    )


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout current session.

    Revokes the whole session, so the refresh token issued alongside the
    presented access token stops working too. Revoking only the access token
    would leave the session refreshable for the remainder of the refresh
    token's lifetime.
    """
    service = _get_auth_service()
    expires_at = current_user.get("exp")

    session_id = current_user.get("sid")
    if session_id:
        service.revoke_session(session_id, expires_at)

    # Tokens issued before sessions were stamped into the access token carry no
    # `sid`. Revoking the individual jti is all that is possible for those, and
    # they age out within the access-token lifetime.
    if current_user.get("jti"):
        service.revoke_token_id(current_user["jti"], expires_at)

    return {"success": True, "message": "Logged out successfully"}


@router.post("/password/reset")
async def request_password_reset(request: PasswordResetRequest):
    """Request a password reset email.

    The response is identical whether or not the address exists, so this
    endpoint cannot be used to enumerate accounts. Request bursts are
    throttled per address using a dedicated password-reset attempt budget
    so reset spam cannot lock out account login (SCOPE_ACCOUNT).
    """
    service = _get_auth_service()
    identity = request.email.lower()
    state = service.attempt_limiter.check(identity, SCOPE_PASSWORD_RESET)
    if state.locked:
        retry_after = max(1, state.retry_after_seconds)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=build_rate_limit_error_payload(
                retry_after_seconds=retry_after,
                limit_type="password_reset",
            ),
            headers={"Retry-After": str(retry_after)},
        )
    service.attempt_limiter.record_failure(identity, SCOPE_PASSWORD_RESET)
    record = service.user_store.get_by_email(request.email)
    if record is not None:
        token = service.reset_token_store.issue(record.user_id)
        try:
            service.notification_sender.send_password_reset(record.email, token)
        except Exception as exc:
            # A delivery failure must not change the response, or the
            # difference becomes the enumeration oracle this avoids.
            logger.error("Password reset dispatch failed: %s", exc)

    return {
        "success": True,
        "message": "If email exists, password reset instructions have been sent",
    }


@router.post("/password/reset/confirm")
async def confirm_password_reset(request: PasswordResetConfirm):
    """Confirm a password reset with a single-use token."""
    service = _get_auth_service()
    user_id = service.reset_token_store.consume(request.token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token is invalid, expired, or already used",
        )

    try:
        service.set_password(user_id, request.new_password)
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # A reset is a recovery action, so every existing session is ended — the
    # attacker who prompted the reset must not keep a live session.
    revoked = service.session_store.revoke_all_for_user(user_id)
    service.reset_token_store.invalidate_for_user(user_id)

    return {
        "success": True,
        "message": "Password has been reset successfully",
        "sessions_revoked": revoked,
    }


@router.post("/password/change")
async def change_password(
    request: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user),
):
    """Change the password for the authenticated user."""
    service = _get_auth_service()
    try:
        service.change_password(
            current_user["user_id"],
            request.current_password,
            request.new_password,
        )
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        )
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))

    # Sign out the user's other devices. A password change is usually a
    # response to suspected compromise, so leaving them signed in would defeat
    # the point.
    revoked = service.session_store.revoke_all_for_user(
        current_user["user_id"], except_session=current_user.get("sid")
    )
    service.reset_token_store.invalidate_for_user(current_user["user_id"])

    return {
        "success": True,
        "message": "Password changed successfully",
        "other_sessions_revoked": revoked,
    }


@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    record = _get_auth_service().user_store.get_by_id(current_user["user_id"])
    return {
        "id": current_user["user_id"],
        "email": current_user["email"],
        "organization_id": current_user["organization_id"],
        "role": current_user["role"],
        "mfa_enabled": bool(record.mfa_enabled) if record else False,
        "sso_provider": None,
    }


@router.get("/sessions")
async def list_active_sessions(current_user: dict = Depends(get_current_user)):
    """List the caller's active sessions.

    Previously returned two invented sessions with fabricated IPs, which is
    worse than returning nothing: a user checking for unauthorised access saw a
    device that was not theirs and could not tell it from a real intrusion.
    """
    service = _get_auth_service()
    current_sid = current_user.get("sid")
    sessions = service.session_store.list_for_user(current_user["user_id"])

    return {
        "sessions": [
            {
                "id": s.session_id,
                "device": s.device,
                "ip_address": s.ip_address,
                "created_at": s.created_at.isoformat(),
                "last_active": s.last_seen_at.isoformat(),
                "current": s.session_id == current_sid,
            }
            for s in sessions
        ],
        "total": len(sessions),
    }


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Revoke one of the caller's own sessions."""
    service = _get_auth_service()
    record = service.session_store.get(session_id)

    # Ownership is checked before existence is revealed, so a caller cannot
    # probe for other users' session ids by comparing 403 against 404.
    if record is None or record.user_id != current_user["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    if not service.session_store.revoke(session_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Session is already revoked",
        )

    return {"success": True, "message": "Session revoked", "session_id": session_id}


@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    request: APIKeyCreateRequest,
    current_user: dict = Depends(get_current_user),
):
    """Create a new API key.

    The raw key is returned exactly once; only its SHA-256 hash is stored.
    Previously the hash was computed and then discarded, so the key returned to
    the caller could never authenticate.
    """
    if request.expires_at is not None:
        expires_at = request.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="expires_at must be in the future",
            )
    else:
        expires_at = None

    raw_key, record = _get_auth_service().api_key_store.create(
        name=request.name,
        organization_id=current_user["organization_id"],
        user_id=current_user["user_id"],
        scopes=request.scopes,
        expires_at=expires_at,
    )

    return APIKeyResponse(
        id=record.key_id,
        name=record.name,
        key=raw_key,
        key_prefix=record.key_prefix,
        scopes=record.scopes,
        expires_at=record.expires_at,
        created_at=record.created_at,
    )


@router.get("/api-keys")
async def list_api_keys(current_user: dict = Depends(get_current_user)):
    """List the organization's API keys.

    Only prefixes are returned — the raw key is unrecoverable by design.
    """
    records = _get_auth_service().api_key_store.list_for_organization(
        current_user["organization_id"]
    )
    return {
        "api_keys": [
            {
                "id": r.key_id,
                "name": r.name,
                "key_prefix": r.key_prefix,
                "scopes": r.scopes,
                "is_active": r.is_active(),
                "last_used": r.last_used_at.isoformat() if r.last_used_at else None,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "created_at": r.created_at.isoformat(),
            }
            for r in records
        ],
        "total": len(records),
    }


@router.delete("/api-keys/{key_id}")
async def delete_api_key(
    key_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Revoke an API key owned by the caller's organization."""
    revoked = _get_auth_service().api_key_store.revoke(
        key_id, current_user["organization_id"]
    )
    if not revoked:
        # Uniform 404 whether the key belongs to another organization or does
        # not exist, so key ids cannot be probed across tenants.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    return {"success": True, "message": "API key deleted", "id": key_id}
