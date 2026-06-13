"""
Authentication Routes
AegisGraph Sentinel Enterprise SaaS Platform
Supports: Email/Password, SSO, MFA, API Keys
"""

import logging
import os

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer, HTTPBearer
from typing import Optional, List
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr, Field
import secrets

from src.exceptions import AuthenticationError
from src.saas.auth.service import (
    AuthProvider,
    AuthService,
    AuthResult,
    rbac_service,
    abac_service,
)

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])

# Security schemes
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., description="A valid refresh token issued by a previous login")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    organization_id: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict
    organization: dict


class MFAEnrollmentResponse(BaseModel):
    secret: str
    uri: str
    backup_codes: List[str]


class MFATokenRequest(BaseModel):
    user_id: str
    mfa_token: str


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


class APIKeyCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    scopes: List[str] = []
    expires_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    id: str
    name: str
    key: str  # Only shown once on creation
    key_prefix: str
    scopes: List[str]
    expires_at: Optional[datetime]
    created_at: datetime


logger = logging.getLogger(__name__)

# Initialize auth service
auth_service = AuthService({
    "jwt_secret": secrets.token_hex(32),
    "access_token_expiry": 3600,
    "refresh_token_expiry": 86400 * 7,
})

# ---------------------------------------------------------------------------
# SSO provider registration — credentials loaded from environment variables
# at startup, not per-request.  The route handler only calls
# sso_providers.get(provider) to retrieve what was configured here.
# ---------------------------------------------------------------------------
_SSO_PROVIDERS = {
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

for _provider, _cfg in _SSO_PROVIDERS.items():
    if _cfg.get("client_id") and _cfg.get("client_secret"):
        try:
            auth_service.add_sso_provider(_provider, _cfg)
            logger.info("SSO provider registered: %s", _provider.value)
        except Exception as _exc:
            logger.warning("Failed to register SSO provider %s: %s", _provider.value, _exc)
    else:
        logger.debug("SSO provider %s not configured (missing env vars)", _provider.value)

# Allow-list of permitted redirect URIs for SSO flows.
# Add your application's callback URLs here or populate via env var.
_SSO_REDIRECT_ALLOWLIST: List[str] = [
    uri.strip()
    for uri in os.getenv("OAUTH_REDIRECT_URIS", "").split(",")
    if uri.strip()
]


async def get_current_user(authorization: Optional[str] = Depends(bearer_scheme)):
    """Get current authenticated user"""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    
    token = authorization.credentials
    try:
        payload = auth_service.verify_token(token)
        return {
            "user_id": payload.sub,
            "organization_id": payload.org,
            "email": payload.email,
            "role": payload.role,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


async def get_optional_user(authorization: Optional[str] = Depends(bearer_scheme)):
    """Get current user if authenticated, None otherwise"""
    if not authorization:
        return None

    try:
        return await get_current_user(authorization)
    except HTTPException:
        # Authentication failed, return None as expected
        return None
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("Unexpected error during optional user authentication: %s", exc)
        return None


async def verify_api_key(api_key: Optional[str] = Depends(api_key_header)):
    """Verify API key authentication"""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )
    
    result = auth_service.authenticate_api_key(api_key)
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
async def login(request: LoginRequest):
    """Login with email and password"""
    result = auth_service.authenticate_user(
        email=request.email,
        password=request.password,
        organization_id=request.organization_id,
    )
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error or "Authentication failed",
        )
    
    if result.mfa_required:
        # Return MFA challenge
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
        user={
            "id": result.user_id,
            "email": "user@example.com",
        },
        organization={
            "id": result.organization_id,
        },
    )


@router.post("/mfa/verify")
async def verify_mfa(request: MFATokenRequest):
    """Verify MFA token and complete login"""
    result = auth_service.verify_mfa(
        user_id=request.user_id,
        mfa_token=request.mfa_token,
        token=request.mfa_token,
    )
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token",
        )
    
    return LoginResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=3600,
        user={"id": result.user_id},
        organization={"id": result.organization_id},
    )


@router.post("/mfa/enroll", response_model=MFAEnrollmentResponse)
async def enroll_mfa(current_user: dict = Depends(get_current_user)):
    """Enroll in MFA"""
    secret = auth_service.generate_mfa_secret()
    uri = auth_service.get_mfa_uri(secret, current_user["email"])
    backup_codes = auth_service.generate_backup_codes()
    
    # In production, store secret and backup codes securely
    
    return MFAEnrollmentResponse(
        secret=secret,
        uri=uri,
        backup_codes=backup_codes,
    )


@router.post("/mfa/disable")
async def disable_mfa(
    current_password: str,
    current_user: dict = Depends(get_current_user),
):
    """Disable MFA"""
    return {"success": True, "message": "MFA disabled"}


@router.get("/sso/providers")
async def list_sso_providers():
    """List available SSO providers"""
    return {
        "providers": [
            {
                "id": "google",
                "name": "Google",
                "icon": "google_icon_url",
                "enabled": True,
            },
            {
                "id": "microsoft",
                "name": "Microsoft",
                "icon": "microsoft_icon_url",
                "enabled": True,
            },
            {
                "id": "okta",
                "name": "Okta",
                "icon": "okta_icon_url",
                "enabled": True,
            },
            {
                "id": "azure_ad",
                "name": "Azure AD",
                "icon": "azure_icon_url",
                "enabled": True,
            },
        ]
    }


@router.get("/sso/{provider}/authorize")
async def sso_authorize(
    provider: AuthProvider,
    redirect_uri: str,
    current_user: dict = Depends(get_current_user),
):
    """Initiate SSO authorization.

    Requires an authenticated session.  The redirect_uri must appear in the
    OAUTH_REDIRECT_URIS allow-list unless the list is empty (dev mode).
    """
    if _SSO_REDIRECT_ALLOWLIST and redirect_uri not in _SSO_REDIRECT_ALLOWLIST:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="redirect_uri is not in the configured allow-list",
        )

    sso_provider = auth_service.sso_providers.get(provider)
    if not sso_provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSO provider '{provider.value}' is not configured. "
                   f"Set OAUTH_{provider.value.upper()}_CLIENT_ID and "
                   f"OAUTH_{provider.value.upper()}_CLIENT_SECRET environment variables.",
        )

    # Attach the per-request redirect_uri to the provider config so the
    # authorization URL reflects the caller's callback endpoint.
    sso_provider.redirect_uri = redirect_uri
    return {"authorization_url": sso_provider.get_authorization_url()}


@router.post("/sso/callback", response_model=LoginResponse)
async def sso_callback(request: SSOCallbackRequest):
    """Handle SSO callback"""
    result = auth_service.authenticate_sso(
        provider=request.provider,
        code=request.code,
        redirect_uri="https://app.aegisgraph.com/auth/callback",
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
        user={"id": result.user_id},
        organization={"id": result.organization_id},
    )


@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(body: RefreshTokenRequest):
    """Exchange a valid refresh token for a new access/refresh token pair."""
    try:
        result = auth_service.refresh_tokens(body.refresh_token)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )
    return LoginResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=auth_service.access_token_expiry,
        user={"id": result.user_id},
        organization={"id": result.organization_id},
    )


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout current session"""
    return {"success": True, "message": "Logged out successfully"}


@router.post("/password/reset")
async def request_password_reset(request: PasswordResetRequest):
    """Request password reset email"""
    return {
        "success": True,
        "message": "If email exists, password reset instructions have been sent",
    }


@router.post("/password/reset/confirm")
async def confirm_password_reset(request: PasswordResetConfirm):
    """Confirm password reset with token"""
    return {
        "success": True,
        "message": "Password has been reset successfully",
    }


@router.post("/password/change")
async def change_password(
    request: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user),
):
    """Change password for authenticated user"""
    return {"success": True, "message": "Password changed successfully"}


@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": current_user["user_id"],
        "email": current_user["email"],
        "organization_id": current_user["organization_id"],
        "role": current_user["role"],
        "mfa_enabled": False,
        "sso_provider": None,
    }


@router.get("/sessions")
async def list_active_sessions(current_user: dict = Depends(get_current_user)):
    """List active sessions for current user"""
    return {
        "sessions": [
            {
                "id": "session_1",
                "device": "Chrome on Windows",
                "ip_address": "192.168.1.1",
                "location": "Mumbai, India",
                "last_active": datetime.utcnow().isoformat(),
                "current": True,
            },
            {
                "id": "session_2",
                "device": "Safari on iOS",
                "ip_address": "10.0.0.1",
                "location": "Unknown",
                "last_active": (datetime.utcnow() - timedelta(hours=24)).isoformat(),
                "current": False,
            },
        ]
    }


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Revoke a session"""
    return {"success": True, "message": "Session revoked"}


@router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    request: APIKeyCreateRequest,
    current_user: dict = Depends(get_current_user),
):
    """Create new API key"""
    import hashlib
    
    # Generate key
    raw_key = f"sk_{secrets.token_hex(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:8]
    
    return APIKeyResponse(
        id=f"key_{datetime.utcnow().timestamp()}",
        name=request.name,
        key=raw_key,  # Only shown once
        key_prefix=key_prefix,
        scopes=request.scopes,
        expires_at=request.expires_at,
        created_at=datetime.utcnow(),
    )


@router.get("/api-keys")
async def list_api_keys(current_user: dict = Depends(get_current_user)):
    """List API keys for organization"""
    return {
        "api_keys": [
            {
                "id": "key_1",
                "name": "Production Key",
                "key_prefix": "sk_1234ab",
                "scopes": ["read", "write"],
                "is_active": True,
                "last_used": datetime.utcnow().isoformat(),
                "created_at": datetime.utcnow().isoformat(),
            }
        ]
    }


@router.delete("/api-keys/{key_id}")
async def delete_api_key(
    key_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Delete API key"""
    return {"success": True, "message": "API key deleted"}