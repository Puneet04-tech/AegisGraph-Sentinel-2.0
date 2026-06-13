"""
Identity Federation Data Models

Defines all data structures for the Identity Federation Platform.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, validator


class IdentityProviderType(str, Enum):
    """Supported Identity Provider types."""
    SAML = "saml"
    OIDC = "oidc"
    OAUTH2 = "oauth2"
    LDAP = "ldap"
    AZURE_AD = "azure_ad"
    OKTA = "okta"
    AUTH0 = "auth0"
    GOOGLE = "google"
    KEYCLOAK = "keycloak"
    PING_IDENTITY = "ping_identity"
    ONELOGIN = "onelogin"


class SSOProvider(str, Enum):
    """SSO Provider types."""
    AZURE_AD = "azure_ad"
    MICROSOFT_ENTRA = "microsoft_entra"
    OKTA = "okta"
    AUTH0 = "auth0"
    GOOGLE_WORKSPACE = "google_workspace"
    KEYCLOAK = "keycloak"
    PING_IDENTITY = "ping_identity"
    ONELOGIN = "onelogin"


class TokenType(str, Enum):
    """OAuth2/OIDC Token types."""
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    ID_TOKEN = "id_token"
    AUTHORIZATION_CODE = "authorization_code"


class SessionState(str, Enum):
    """Federation session states."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALIDATED = "invalidated"


class IdentityProvider(BaseModel):
    """Identity Provider configuration."""
    id: str = Field(..., description="Unique provider identifier")
    name: str = Field(..., description="Provider display name")
    provider_type: IdentityProviderType = Field(..., description="Type of IdP")
    sso_provider: Optional[SSOProvider] = Field(None, description="SSO provider type")
    enabled: bool = Field(default=True, description="Whether provider is enabled")
    
    # Connection settings
    issuer: str = Field(..., description="Provider issuer URL")
    metadata_url: Optional[str] = Field(None, description="SAML/OIDC metadata URL")
    client_id: Optional[str] = Field(None, description="OAuth2/OIDC client ID")
    client_secret: Optional[str] = Field(None, description="OAuth2/OIDC client secret")
    
    # SAML settings
    saml_entity_id: Optional[str] = Field(None, description="SAML Entity ID")
    saml_sso_url: Optional[str] = Field(None, description="SAML SSO URL")
    saml_slo_url: Optional[str] = Field(None, description="SAML SLO URL")
    saml_certificate: Optional[str] = Field(None, description="SAML signing certificate")
    
    # OIDC settings
    oidc_discovery_url: Optional[str] = Field(None, description="OIDC discovery URL")
    oidc_authorization_endpoint: Optional[str] = Field(None, description="OIDC auth endpoint")
    oidc_token_endpoint: Optional[str] = Field(None, description="OIDC token endpoint")
    oidc_userinfo_endpoint: Optional[str] = Field(None, description="OIDC userinfo endpoint")
    oidc_jwks_uri: Optional[str] = Field(None, description="OIDC JWKS URI")
    
    # Attribute mapping
    attribute_mappings: dict[str, str | list[str]] = Field(
        default_factory=dict,
        description="Mapping from IdP attributes to local attributes"
    )
    role_mappings: list["RoleMapping"] = Field(
        default_factory=list,
        description="Role mapping rules"
    )
    
    # Security settings
    sign_requests: bool = Field(default=True, description="Sign SAML requests")
    want_assertions_signed: bool = Field(default=True, description="Require signed assertions")
    validate_signature: bool = Field(default=True, description="Validate IdP signatures")
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        use_enum_values = True


class FederatedUser(BaseModel):
    """Federated user identity."""
    id: str = Field(..., description="Local user ID")
    provider_id: str = Field(..., description="Identity Provider ID")
    provider_user_id: str = Field(..., description="User ID from IdP")
    
    # User attributes
    email: str = Field(..., description="User email")
    username: Optional[str] = Field(None, description="Local username")
    display_name: Optional[str] = Field(None, description="Display name")
    first_name: Optional[str] = Field(None, description="First name")
    last_name: Optional[str] = Field(None, description="Last name")
    groups: list[str] = Field(default_factory=list, description="User groups from IdP")
    roles: list[str] = Field(default_factory=list, description="Mapped roles")
    
    # Profile data from IdP
    profile_data: dict = Field(default_factory=dict, description="Raw profile data")
    claims: dict = Field(default_factory=dict, description="Validated claims")
    
    # Status
    enabled: bool = Field(default=True)
    mfa_enabled: bool = Field(default=False)
    last_login: Optional[datetime] = Field(None)
    provisioning_status: str = Field(default="pending")
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    @validator("email")
    def validate_email(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError("Invalid email format")
        return v.lower()


class FederationSession(BaseModel):
    """Active federation session."""
    id: str = Field(..., description="Session ID")
    user_id: str = Field(..., description="User ID")
    provider_id: str = Field(..., description="Identity Provider ID")
    
    # Token information
    access_token: Optional[str] = Field(None, description="OAuth2/OIDC access token")
    refresh_token: Optional[str] = Field(None, description="Refresh token")
    id_token: Optional[str] = Field(None, description="OIDC ID token")
    token_type: TokenType = Field(default=TokenType.ACCESS_TOKEN)
    
    # Session state
    state: SessionState = Field(default=SessionState.ACTIVE)
    session_index: Optional[str] = Field(None, description="SAML session index")
    
    # Request/Response data
    relay_state: Optional[str] = Field(None, description="SAML relay state")
    nonce: Optional[str] = Field(None, description="OIDC nonce")
    
    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(..., description="Session expiration time")
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    
    # Security
    ip_address: Optional[str] = Field(None)
    user_agent: Optional[str] = Field(None)
    
    # Metadata
    metadata: dict = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True
    
    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at


class AuthenticationRequest(BaseModel):
    """Identity federation authentication request."""
    provider_id: str = Field(..., description="Identity Provider ID")
    return_url: Optional[str] = Field(None, description="URL to redirect after auth")
    
    # Flow type
    flow_type: str = Field(default="sso", description="Authentication flow type")
    
    # SAML specific
    saml_request_id: Optional[str] = Field(None)
    saml_force_authn: bool = Field(default=False)
    
    # OIDC specific
    oidc_prompt: Optional[str] = Field(None)
    oidc_max_age: Optional[int] = Field(None)
    oidc_acr_values: Optional[str] = Field(None)
    
    # OAuth2 specific
    oauth2_scope: Optional[str] = Field(None)
    oauth2_response_type: Optional[str] = Field(None)
    
    # Security
    relay_state: Optional[str] = Field(None)
    nonce: Optional[str] = Field(None)
    
    # Context
    ip_address: Optional[str] = Field(None)
    user_agent: Optional[str] = Field(None)


class AuthenticationResponse(BaseModel):
    """Identity federation authentication response."""
    success: bool = Field(..., description="Authentication success status")
    
    # User information
    user: Optional[FederatedUser] = Field(None)
    session: Optional[FederationSession] = Field(None)
    
    # Tokens (for programmatic access)
    access_token: Optional[str] = Field(None)
    id_token: Optional[str] = Field(None)
    refresh_token: Optional[str] = Field(None)
    
    # Redirect
    redirect_url: Optional[str] = Field(None)
    
    # Error information
    error: Optional[str] = Field(None)
    error_description: Optional[str] = Field(None)
    error_uri: Optional[str] = Field(None)
    
    # Audit
    provider_id: Optional[str] = Field(None)
    authentication_method: Optional[str] = Field(None)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class RoleMapping(BaseModel):
    """Role mapping from IdP groups to local roles."""
    id: str = Field(..., description="Mapping ID")
    provider_id: str = Field(..., description="Identity Provider ID")
    
    # Source (from IdP)
    source_group: str = Field(..., description="IdP group name")
    source_type: str = Field(default="group", description="Source type (group, role, claim)")
    
    # Target (local)
    target_role: str = Field(..., description="Local role name")
    target_permission_level: int = Field(default=1, description="Permission level (1-5)")
    
    # Conditions
    conditions: dict = Field(default_factory=dict, description="Mapping conditions")
    
    # Status
    enabled: bool = Field(default=True)
    priority: int = Field(default=0, description="Mapping priority (higher = first)")
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class IdentityMapping(BaseModel):
    """Identity attribute mapping from IdP to local user."""
    id: str = Field(..., description="Mapping ID")
    provider_id: str = Field(..., description="Identity Provider ID")
    
    # Source attribute
    source_attribute: str = Field(..., description="IdP attribute name")
    source_namespace: Optional[str] = Field(None, description="SAML attribute namespace")
    
    # Target attribute
    target_attribute: str = Field(..., description="Local attribute name")
    
    # Transformation
    transform_type: str = Field(default="direct", description="Transform type")
    transform_function: Optional[str] = Field(None, description="Custom transform function")
    default_value: Optional[str] = Field(None, description="Default if source is empty")
    
    # Status
    enabled: bool = Field(default=True)
    required: bool = Field(default=False, description="Required for provisioning")
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ProvisioningEvent(BaseModel):
    """User provisioning event."""
    id: str = Field(..., description="Event ID")
    user_id: str = Field(..., description="User ID")
    provider_id: str = Field(..., description="Identity Provider ID")
    
    # Event type
    event_type: str = Field(..., description="Provisioning event type")
    # Types: create, update, delete, disable, enable, sync, deprovision
    
    # Status
    status: str = Field(..., description="Event status")
    # Statuses: pending, in_progress, completed, failed, cancelled
    
    # Changes
    previous_values: dict = Field(default_factory=dict)
    new_values: dict = Field(default_factory=dict)
    changes: list[str] = Field(default_factory=list)
    
    # Error information
    error_message: Optional[str] = Field(None)
    retry_count: int = Field(default=0)
    
    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = Field(None)
    completed_at: Optional[datetime] = Field(None)
    
    # Context
    triggered_by: str = Field(default="system", description="What triggered the event")
    request_id: Optional[str] = Field(None)


class AuditEvent(BaseModel):
    """Identity federation audit event."""
    id: str = Field(..., description="Event ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Actor
    user_id: Optional[str] = Field(None)
    username: Optional[str] = Field(None)
    ip_address: Optional[str] = Field(None)
    
    # Action
    action: str = Field(..., description="Action performed")
    resource_type: str = Field(..., description="Resource type")
    resource_id: Optional[str] = Field(None)
    
    # Result
    success: bool = Field(default=True)
    error_message: Optional[str] = Field(None)
    
    # Context
    provider_id: Optional[str] = Field(None)
    session_id: Optional[str] = Field(None)
    authentication_method: Optional[str] = Field(None)
    
    # Additional data
    metadata: dict = Field(default_factory=dict)
    user_agent: Optional[str] = Field(None)


# Re-export for convenience
IdentityProvider.model_rebuild()
FederatedUser.model_rebuild()
RoleMapping.model_rebuild()