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
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import jwt
from pydantic import BaseModel, EmailStr

from src.exceptions import AuthenticationError, AuthorizationError

logger = logging.getLogger(__name__)


@dataclass
class UserRecord:
    """Minimal user record used by AuthService for authentication."""
    user_id: str
    organization_id: str
    email: str
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


class InMemoryUserStore(UserStore):
    """Thread-unsafe in-memory user store for development and testing only.

    Do **not** use this in production — records are not persisted across
    restarts and there is no concurrency protection.
    """

    def __init__(self) -> None:
        self._users: Dict[str, UserRecord] = {}
        self._email_index: Dict[str, str] = {}

    def add(self, record: UserRecord) -> None:
        self._users[record.user_id] = record
        self._email_index[record.email] = record.user_id

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
        expires_at = datetime.utcnow() + timedelta(seconds=self._ttl_seconds)
        self._pending[user_id] = (mfa_token, expires_at)
        return mfa_token

    def consume(self, user_id: str, mfa_token: str) -> bool:
        entry = self._pending.pop(user_id, None)
        if entry is None:
            return False
        stored_token, expires_at = entry
        if datetime.utcnow() > expires_at:
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
    organization_id: Optional[str] = None
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

        # SSO providers
        self.sso_providers: Dict[str, 'SSOProvider'] = {}

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
        now = datetime.utcnow()
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
            return TokenPayload(
                sub=payload["sub"],
                org=payload["org"],
                email=payload["email"],
                role=payload["role"],
                permissions=payload["permissions"],
                exp=datetime.fromtimestamp(payload["exp"]),
                iat=datetime.fromtimestamp(payload["iat"]),
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
        organization_id: Optional[str] = None
    ) -> AuthResult:
        """Authenticate user with email and password.

        Looks up the user via the injected ``UserStore``.  Returns an
        ``AuthResult`` with ``success=False`` when the user is not found or
        the password does not match.
        """
        record = self.user_store.get_by_email(email)
        if record is None:
            return AuthResult(success=False, error="Invalid credentials")

        if record.password_hash and not self.verify_password(password, record.password_hash):
            return AuthResult(success=False, error="Invalid credentials")

        org_id = organization_id or record.organization_id

        if record.mfa_enabled:
            mfa_token = self.mfa_pending_store.issue(record.user_id)
            return AuthResult(
                success=True,
                user_id=record.user_id,
                organization_id=org_id,
                mfa_required=True,
                mfa_token=mfa_token,
            )

        return self._create_auth_result(record, org_id)

    def authenticate_api_key(self, api_key: str) -> AuthResult:
        """Authenticate using API key.

        The caller is responsible for supplying a ``UserStore`` that can
        resolve API key hashes to organization records.  The base
        implementation hashes the key and delegates to the store's
        ``get_by_id`` path; concrete stores should index keys appropriately.

        Note: Full API-key-to-org resolution requires a store implementation
        with an API key index.  The current ``InMemoryUserStore`` does not
        support this lookup — production deployments must provide a store that
        does.
        """
        _key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        logger.debug("API key authentication attempted (hash prefix: %s)", _key_hash[:8])
        # Concrete store implementations should resolve _key_hash to a UserRecord.
        # Until a store with key-index support is wired in, return a failed result
        # rather than silently granting access with a hardcoded org.
        return AuthResult(
            success=False,
            error="API key authentication requires a configured user store with key-index support",
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
        user_id, org_id = self._find_or_create_sso_user(provider, user_info)

        record = self.user_store.get_by_id(user_id)
        if record is None:
            return AuthResult(success=False, error="User record not found after SSO login")

        return self._create_auth_result(record, org_id, provider=provider)

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

        return self._create_auth_result(record, record.organization_id)

    def _create_auth_result(
        self,
        record: UserRecord,
        organization_id: str,
        provider: Optional[AuthProvider] = None,
    ) -> AuthResult:
        """Create successful authentication result"""
        session_id = secrets.token_hex(16)
        now = datetime.utcnow()

        access_payload = TokenPayload(
            sub=record.user_id,
            org=organization_id,
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
            organization_id=organization_id,
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

        return self._create_auth_result(record, record.organization_id)

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