"""
Enterprise Identity Federation Platform

Provides centralized authentication, SSO, SAML 2.0, OIDC, OAuth2,
and Identity Provider integration for AegisGraph Sentinel.
"""

from .models import (
    IdentityProvider,
    IdentityProviderType,
    FederatedUser,
    FederationSession,
    AuthenticationRequest,
    AuthenticationResponse,
    RoleMapping,
    IdentityMapping,
    ProvisioningEvent,
    AuditEvent,
    SSOProvider,
    TokenType,
    SessionState,
)
from .store import IdentityFederationStore
from .providers import IdentityProviderRegistry
from .saml_provider import SAMLProvider
from .oidc_provider import OIDCProvider
from .oauth_provider import OAuthProvider
from .federation_manager import FederationManager
from .session_manager import SessionManager
from .identity_mapper import IdentityMapper
from .provisioning import ProvisioningService
from .audit import AuditLogger
from .service import IdentityFederationService

__all__ = [
    # Models
    "IdentityProvider",
    "IdentityProviderType",
    "FederatedUser",
    "FederationSession",
    "AuthenticationRequest",
    "AuthenticationResponse",
    "RoleMapping",
    "IdentityMapping",
    "ProvisioningEvent",
    "AuditEvent",
    "SSOProvider",
    "TokenType",
    "SessionState",
    # Store
    "IdentityFederationStore",
    # Providers
    "IdentityProviderRegistry",
    "SAMLProvider",
    "OIDCProvider",
    "OAuthProvider",
    # Managers
    "FederationManager",
    "SessionManager",
    # Services
    "IdentityMapper",
    "ProvisioningService",
    "AuditLogger",
    "IdentityFederationService",
]

__version__ = "1.0.0"