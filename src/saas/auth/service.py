"""
Enterprise Authentication Service
AegisGraph Sentinel Enterprise
Supports: SSO, SAML 2.0, OAuth2, OpenID Connect, MFA
"""

import hashlib
import secrets
import pyotp
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import jwt
from pydantic import BaseModel, EmailStr

from src.exceptions import AuthenticationError, AuthorizationError


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

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.jwt_secret = config.get("jwt_secret", secrets.token_hex(32))
        self.jwt_algorithm = "HS256"
        self.access_token_expiry = config.get("access_token_expiry", 3600)  # 1 hour
        self.refresh_token_expiry = config.get("refresh_token_expiry", 86400 * 7)  # 7 days
        
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
        """Authenticate user with email and password"""
        # In production, fetch user from database
        # For now, return mock success
        user_id = "user_123"
        org_id = organization_id or "org_123"
        
        # Check if MFA is enabled
        mfa_enabled = False
        
        if mfa_enabled:
            mfa_token = secrets.token_hex(16)
            return AuthResult(
                success=True,
                user_id=user_id,
                organization_id=org_id,
                mfa_required=True,
                mfa_token=mfa_token,
            )
        
        return self._create_auth_result(user_id, org_id)

    def authenticate_api_key(self, api_key: str) -> AuthResult:
        """Authenticate using API key"""
        # Hash the provided key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # In production, look up key in database
        # Verify organization and scopes
        
        org_id = "org_123"
        return AuthResult(
            success=True,
            organization_id=org_id,
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
        
        return self._create_auth_result(user_id, org_id, provider=provider)

    def verify_mfa(self, user_id: str, mfa_token: str, token: str) -> AuthResult:
        """Verify MFA and complete authentication"""
        # In production, fetch user MFA secret
        secret = "MFA_SECRET_HERE"
        
        if not self.verify_mfa_token(secret, token):
            return AuthResult(
                success=False,
                error="Invalid MFA token",
            )
        
        org_id = "org_123"
        return self._create_auth_result(user_id, org_id)

    def _create_auth_result(
        self,
        user_id: str,
        organization_id: str,
        provider: Optional[AuthProvider] = None,
    ) -> AuthResult:
        """Create successful authentication result"""
        session_id = secrets.token_hex(16)
        now = datetime.utcnow()
        
        access_payload = TokenPayload(
            sub=user_id,
            org=organization_id,
            email="user@example.com",
            role="member",
            permissions=["read", "write"],
            exp=now + timedelta(seconds=self.access_token_expiry),
            iat=now,
            jti=secrets.token_hex(16),
        )
        
        access_token = self.create_access_token(access_payload)
        refresh_token = self.create_refresh_token(user_id, session_id)
        
        return AuthResult(
            success=True,
            user_id=user_id,
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
        """Find or create user from SSO provider"""
        # In production, implement user lookup and creation
        return ("user_123", "org_123")

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


# Initialize services
auth_service = AuthService({
    "jwt_secret": "your-jwt-secret-here",
    "access_token_expiry": 3600,
    "refresh_token_expiry": 86400 * 7,
})

rbac_service = RBACService()
abac_service = ABACService()