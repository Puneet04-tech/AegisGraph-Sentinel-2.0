"""
Identity Federation Service

Unified service providing enterprise identity federation capabilities.
"""

from datetime import datetime
from typing import Optional

from .models import (
    IdentityProvider,
    FederatedUser,
    FederationSession,
    AuthenticationRequest,
    AuthenticationResponse,
    IdentityProviderType,
    SSOProvider,
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


class IdentityFederationService:
    """
    Unified Identity Federation Service.
    
    Provides a single entry point for all identity federation operations:
    - Identity Provider management
    - Authentication (SAML, OIDC, OAuth2)
    - Session management
    - Role synchronization
    - Audit logging
    """
    
    def __init__(
        self,
        service_provider_id: str = "aegisgraph-sentinel",
        issuer: str = "https://aegisgraph.example.com",
        session_ttl: int = 3600,
        auto_provision: bool = True,
        audit_retention_days: int = 90,
    ):
        # Initialize store
        self._store = IdentityFederationStore(session_ttl=session_ttl)
        
        # Initialize components
        self._registry = IdentityProviderRegistry(self._store)
        self._saml = SAMLProvider(self._store, service_provider_id)
        self._oidc = OIDCProvider(self._store, issuer)
        self._oauth = OAuthProvider(self._store, issuer)
        self._federation = FederationManager(self._store, service_provider_id, issuer)
        self._sessions = SessionManager(self._store, default_ttl=session_ttl)
        self._mapper = IdentityMapper(self._store)
        self._provisioning = ProvisioningService(
            self._store,
            auto_provision=auto_provision,
        )
        self._audit = AuditLogger(self._store, retention_days=audit_retention_days)
        
        # Service metadata
        self._sp_id = service_provider_id
        self._issuer = issuer
    
    # ==================== Identity Provider Management ====================
    
    def register_provider(
        self,
        name: str,
        provider_type: IdentityProviderType,
        issuer: str,
        sso_provider: Optional[SSOProvider] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        metadata_url: Optional[str] = None,
        **kwargs,
    ) -> tuple[IdentityProvider, bool, list[str]]:
        """
        Register a new identity provider.
        
        Returns:
            Tuple of (provider, is_valid, validation_errors)
        """
        # Register provider
        provider = self._registry.register_provider(
            name=name,
            provider_type=provider_type,
            issuer=issuer,
            sso_provider=sso_provider,
            client_id=client_id,
            client_secret=client_secret,
            metadata_url=metadata_url,
            **kwargs,
        )
        
        # Validate configuration
        is_valid, errors = self._registry.validate_provider(provider)
        
        # Log event
        self._audit.log_provider_event(
            action="register",
            provider_id=provider.id,
            success=is_valid,
            error_message="; ".join(errors) if errors else None,
            metadata={"name": name, "type": provider_type.value},
        )
        
        return provider, is_valid, errors
    
    def get_provider(self, provider_id: str) -> Optional[IdentityProvider]:
        """Get identity provider by ID."""
        return self._registry.get_provider(provider_id)
    
    def list_providers(self, enabled_only: bool = False) -> list[IdentityProvider]:
        """List all registered identity providers."""
        return self._registry.list_providers(enabled_only=enabled_only)
    
    def update_provider(self, provider: IdentityProvider) -> None:
        """Update an identity provider."""
        self._registry.update_provider(provider)
        
        self._audit.log_provider_event(
            action="update",
            provider_id=provider.id,
            metadata={"name": provider.name},
        )
    
    def delete_provider(self, provider_id: str) -> bool:
        """Delete an identity provider."""
        success = self._registry.delete_provider(provider_id)
        
        if success:
            self._audit.log_provider_event(
                action="delete",
                provider_id=provider_id,
            )
        
        return success
    
    def enable_provider(self, provider_id: str) -> bool:
        """Enable an identity provider."""
        success = self._registry.enable_provider(provider_id)
        
        if success:
            self._audit.log_provider_event(
                action="enable",
                provider_id=provider_id,
            )
        
        return success
    
    def disable_provider(self, provider_id: str) -> bool:
        """Disable an identity provider."""
        success = self._registry.disable_provider(provider_id)
        
        if success:
            self._audit.log_provider_event(
                action="disable",
                provider_id=provider_id,
            )
        
        return success
    
    # ==================== Authentication ====================
    
    def authenticate(
        self,
        provider_id: str,
        return_url: Optional[str] = None,
        protocol: Optional[str] = None,
        **kwargs,
    ) -> AuthenticationResponse:
        """
        Initiate authentication with an identity provider.
        
        Args:
            provider_id: Identity Provider ID
            return_url: URL to redirect after authentication
            protocol: Protocol to use (saml, oidc, oauth)
            **kwargs: Protocol-specific options
        
        Returns:
            AuthenticationResponse with redirect URL or error
        """
        # Get provider
        provider = self._registry.get_provider(provider_id)
        if not provider:
            return AuthenticationResponse(
                success=False,
                error="provider_not_found",
                error_description="Identity provider not found",
            )
        
        # Determine protocol
        if not protocol:
            protocol = self._get_protocol_for_provider(provider)
        
        # Create authentication request
        request = AuthenticationRequest(
            provider_id=provider_id,
            return_url=return_url,
            **kwargs,
        )
        
        # Initiate authentication
        response = self._federation.authenticate(request)
        
        # Log authentication attempt
        self._audit.log_authentication(
            success=False,  # Will be updated after callback
            provider_id=provider_id,
            authentication_method=protocol,
            ip_address=kwargs.get("ip_address"),
            user_agent=kwargs.get("user_agent"),
        )
        
        return response
    
    def _get_protocol_for_provider(self, provider: IdentityProvider) -> str:
        """Determine protocol based on provider type."""
        provider_type = provider.provider_type.value if hasattr(provider.provider_type, 'value') else provider.provider_type
        
        if provider_type == "saml":
            return "saml"
        elif provider_type in ["oidc", "azure_ad", "okta", "auth0", "google", "keycloak"]:
            return "oidc"
        elif provider_type == "oauth2":
            return "oauth"
        
        return "unknown"
    
    def handle_callback(
        self,
        provider_id: str,
        protocol: str,
        **kwargs,
    ) -> AuthenticationResponse:
        """Handle authentication callback from IdP."""
        response = self._federation.handle_callback(provider_id, protocol, **kwargs)
        
        # Log result
        if response.success and response.user:
            self._audit.log_authentication(
                success=True,
                provider_id=provider_id,
                user_id=response.user.id,
                username=response.user.username,
                authentication_method=protocol,
                ip_address=kwargs.get("ip_address"),
                user_agent=kwargs.get("user_agent"),
            )
        else:
            self._audit.log_authentication(
                success=False,
                provider_id=provider_id,
                authentication_method=protocol,
                error_message=response.error_description,
                ip_address=kwargs.get("ip_address"),
            )
        
        return response
    
    def sso_login(
        self,
        user_id: str,
        provider_id: str,
        target_url: Optional[str] = None,
    ) -> AuthenticationResponse:
        """Initiate SSO for an existing user."""
        return self._federation.initiate_sso(user_id, provider_id, target_url)
    
    # ==================== User Management ====================
    
    def get_user(self, user_id: str) -> Optional[FederatedUser]:
        """Get federated user by ID."""
        return self._store.get_user(user_id)
    
    def get_user_by_email(self, email: str) -> Optional[FederatedUser]:
        """Get federated user by email."""
        return self._store.get_user_by_email(email)
    
    def list_users(self, provider_id: Optional[str] = None) -> list[FederatedUser]:
        """List federated users."""
        if provider_id:
            return self._store.list_users_by_provider(provider_id)
        return list(self._store._users.values())
    
    def link_provider(
        self,
        user_id: str,
        provider_id: str,
        provider_user_id: str,
    ) -> AuthenticationResponse:
        """Link an identity provider to a user."""
        return self._federation.link_provider(user_id, provider_id, provider_user_id)
    
    def unlink_provider(
        self,
        user_id: str,
        provider_id: str,
    ) -> AuthenticationResponse:
        """Unlink an identity provider from a user."""
        return self._federation.unlink_provider(user_id, provider_id)
    
    def get_federated_identities(self, user_id: str) -> list[dict]:
        """Get all federated identities for a user."""
        return self._federation.get_federated_identities(user_id)
    
    # ==================== Session Management ====================
    
    def validate_session(self, session_id: str) -> tuple[bool, Optional[FederationSession]]:
        """Validate a federation session."""
        return self._sessions.validate_session(session_id)
    
    def refresh_session(self, session_id: str, ttl: Optional[int] = None) -> bool:
        """Refresh a session."""
        return self._sessions.refresh_session(session_id, ttl)
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session."""
        success = self._sessions.revoke_session(session_id)
        
        if success:
            self._audit.log_session(
                action="revoke",
                session_id=session_id,
            )
        
        return success
    
    def revoke_all_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user."""
        count = self._sessions.revoke_user_sessions(user_id)
        
        self._audit.log_session(
            action="revoke_all",
            user_id=user_id,
            metadata={"sessions_revoked": count},
        )
        
        return count
    
    def get_user_sessions(self, user_id: str) -> list[FederationSession]:
        """Get all active sessions for a user."""
        return self._sessions.get_user_sessions(user_id)
    
    # ==================== Token Operations ====================
    
    def exchange_token(
        self,
        provider_id: str,
        grant_type: str,
        code: Optional[str] = None,
        refresh_token: Optional[str] = None,
        **kwargs,
    ) -> AuthenticationResponse:
        """Exchange or refresh tokens."""
        provider = self._registry.get_provider(provider_id)
        if not provider:
            return AuthenticationResponse(
                success=False,
                error="provider_not_found",
            )
        
        if provider.provider_type.value == "oauth2":
            return self._oauth.token(
                grant_type=grant_type,
                code=code,
                refresh_token=refresh_token,
                **kwargs,
            )
        
        return AuthenticationResponse(
            success=False,
            error="unsupported_provider",
        )
    
    def validate_token(self, provider_id: str, token: str) -> tuple[bool, Optional[dict]]:
        """Validate a token."""
        provider = self._registry.get_provider(provider_id)
        if not provider:
            return False, None
        
        return self._oidc.validate_token(provider_id, token)
    
    # ==================== Provisioning ====================
    
    def provision_user(
        self,
        provider_id: str,
        user_info: dict,
    ) -> Optional[FederatedUser]:
        """Provision a user from IdP data."""
        provider = self._registry.get_provider(provider_id)
        if not provider:
            return None
        
        user, event = self._provisioning.provision_user(provider, user_info)
        
        self._audit.log_provisioning(
            action=event.event_type,
            user_id=user.id if user else "",
            provider_id=provider_id,
            success=event.status == "completed",
            error_message=event.error_message,
        )
        
        return user
    
    def deprovision_user(self, user_id: str) -> bool:
        """Deprovision a user."""
        success = self._provisioning.deprovision_user(user_id)
        
        if success:
            self._audit.log_provisioning(
                action="deprovision",
                user_id=user_id,
                provider_id="",
            )
        
        return success
    
    # ==================== Audit ====================
    
    def get_audit_log(
        self,
        user_id: Optional[str] = None,
        provider_id: Optional[str] = None,
        action: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query audit log."""
        events = self._audit.query(
            user_id=user_id,
            provider_id=provider_id,
            action=action,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )
        
        return [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "resource_type": e.resource_type,
                "user_id": e.user_id,
                "success": e.success,
                "error_message": e.error_message,
                "provider_id": e.provider_id,
                "ip_address": e.ip_address,
            }
            for e in events
        ]
    
    def get_user_activity(self, user_id: str, days: int = 30) -> dict:
        """Get activity summary for a user."""
        return self._audit.get_user_activity(user_id, days)
    
    def get_security_summary(self, days: int = 7) -> dict:
        """Get security event summary."""
        return self._audit.get_security_summary(days)
    
    # ==================== Statistics ====================
    
    def get_stats(self) -> dict:
        """Get service statistics."""
        return {
            "store": self._store.get_stats(),
            "audit": self._audit.get_stats(),
            "providers": {
                "total": len(self._store.list_providers()),
                "enabled": len(self._store.list_providers(enabled_only=True)),
            },
            "users": {
                "total": len(self._store._users),
            },
        }
    
    # ==================== Quick Setup ====================
    
    def setup_azure_ad(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        name: str = "Azure AD",
    ) -> IdentityProvider:
        """Quick setup for Azure AD."""
        return self._registry.register_azure_ad(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            name=name,
        )
    
    def setup_okta(
        self,
        domain: str,
        client_id: str,
        client_secret: str,
        name: str = "Okta",
    ) -> IdentityProvider:
        """Quick setup for Okta."""
        return self._registry.register_okta(
            domain=domain,
            client_id=client_id,
            client_secret=client_secret,
            name=name,
        )
    
    def setup_auth0(
        self,
        domain: str,
        client_id: str,
        client_secret: str,
        name: str = "Auth0",
    ) -> IdentityProvider:
        """Quick setup for Auth0."""
        return self._registry.register_auth0(
            domain=domain,
            client_id=client_id,
            client_secret=client_secret,
            name=name,
        )
    
    def setup_google(
        self,
        client_id: str,
        client_secret: str,
        name: str = "Google Workspace",
    ) -> IdentityProvider:
        """Quick setup for Google Workspace."""
        return self._registry.register_google(
            client_id=client_id,
            client_secret=client_secret,
            name=name,
        )