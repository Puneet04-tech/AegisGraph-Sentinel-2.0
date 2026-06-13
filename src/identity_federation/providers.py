"""
Identity Provider Registry

Manages registration and discovery of identity providers.
"""

import hashlib
import uuid
from datetime import datetime
from typing import Optional
from .models import (
    IdentityProvider,
    IdentityProviderType,
    SSOProvider,
)
from .store import IdentityFederationStore


class IdentityProviderRegistry:
    """
    Registry for managing identity providers.
    
    Handles provider registration, validation, and discovery.
    """
    
    # Default attribute mappings for common IdPs
    DEFAULT_ATTRIBUTE_MAPPINGS = {
        "email": ["email", "mail", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"],
        "username": ["username", "preferred_username", "sub"],
        "display_name": ["display_name", "name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"],
        "first_name": ["given_name", "first_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"],
        "last_name": ["surname", "family_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"],
        "groups": ["groups", "roles", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"],
    }
    
    def __init__(self, store: IdentityFederationStore):
        self._store = store
    
    def register_provider(
        self,
        name: str,
        provider_type: IdentityProviderType,
        issuer: str,
        sso_provider: Optional[SSOProvider] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        metadata_url: Optional[str] = None,
        **kwargs
    ) -> IdentityProvider:
        """
        Register a new identity provider.
        
        Args:
            name: Provider display name
            provider_type: Type of IdP (SAML, OIDC, OAuth2)
            issuer: Provider issuer URL
            sso_provider: SSO provider type
            client_id: OAuth2/OIDC client ID
            client_secret: OAuth2/OIDC client secret
            metadata_url: SAML/OIDC metadata URL
            **kwargs: Additional provider settings
        
        Returns:
            Registered IdentityProvider
        """
        provider_id = self._generate_provider_id(issuer, provider_type)
        
        provider = IdentityProvider(
            id=provider_id,
            name=name,
            provider_type=provider_type,
            sso_provider=sso_provider,
            issuer=issuer,
            metadata_url=metadata_url,
            client_id=client_id,
            client_secret=client_secret,
            attribute_mappings=self.DEFAULT_ATTRIBUTE_MAPPINGS.copy(),
            **kwargs
        )
        
        self._store.register_provider(provider)
        return provider
    
    def _generate_provider_id(self, issuer: str, provider_type: IdentityProviderType) -> str:
        """Generate a unique provider ID from issuer and type."""
        hash_input = f"{issuer}:{provider_type.value}".encode()
        return hashlib.sha256(hash_input).hexdigest()[:16]
    
    def get_provider(self, provider_id: str) -> Optional[IdentityProvider]:
        """Get provider by ID."""
        return self._store.get_provider(provider_id)
    
    def get_provider_by_issuer(self, issuer: str) -> Optional[IdentityProvider]:
        """Get provider by issuer URL."""
        providers = self._store.list_providers()
        for provider in providers:
            if provider.issuer == issuer:
                return provider
        return None
    
    def list_providers(self, enabled_only: bool = False) -> list[IdentityProvider]:
        """List all registered providers."""
        return self._store.list_providers(enabled_only=enabled_only)
    
    def list_providers_by_type(
        self, provider_type: IdentityProviderType
    ) -> list[IdentityProvider]:
        """List providers by type."""
        providers = self._store.list_providers()
        return [p for p in providers if p.provider_type == provider_type]
    
    def list_providers_by_sso(
        self, sso_provider: SSOProvider
    ) -> list[IdentityProvider]:
        """List providers by SSO provider type."""
        providers = self._store.list_providers()
        return [p for p in providers if p.sso_provider == sso_provider]
    
    def update_provider(self, provider: IdentityProvider) -> None:
        """Update an existing provider."""
        self._store.update_provider(provider)
    
    def delete_provider(self, provider_id: str) -> bool:
        """Delete a provider."""
        return self._store.delete_provider(provider_id)
    
    def enable_provider(self, provider_id: str) -> bool:
        """Enable a provider."""
        provider = self._store.get_provider(provider_id)
        if provider:
            provider.enabled = True
            provider.updated_at = datetime.utcnow()
            self._store.update_provider(provider)
            return True
        return False
    
    def disable_provider(self, provider_id: str) -> bool:
        """Disable a provider."""
        provider = self._store.get_provider(provider_id)
        if provider:
            provider.enabled = False
            provider.updated_at = datetime.utcnow()
            self._store.update_provider(provider)
            return True
        return False
    
    def validate_provider(self, provider: IdentityProvider) -> tuple[bool, list[str]]:
        """
        Validate provider configuration.
        
        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []
        
        # Check required fields based on type
        if provider.provider_type == IdentityProviderType.SAML:
            if not provider.saml_entity_id:
                errors.append("SAML Entity ID is required")
            if not provider.saml_sso_url:
                errors.append("SAML SSO URL is required")
            if not provider.saml_certificate:
                errors.append("SAML Certificate is required")
        
        elif provider.provider_type in [
            IdentityProviderType.OIDC,
            IdentityProviderType.OAUTH2,
        ]:
            if not provider.client_id:
                errors.append("Client ID is required")
            if not provider.client_secret:
                errors.append("Client Secret is required")
            if not provider.oidc_discovery_url and not provider.oidc_authorization_endpoint:
                errors.append("OIDC Discovery URL or Authorization Endpoint is required")
        
        elif provider.provider_type == IdentityProviderType.AZURE_AD:
            if not provider.client_id:
                errors.append("Client ID is required")
            if not provider.client_secret:
                errors.append("Client Secret is required")
            if not provider.issuer:
                errors.append("Issuer URL is required")
        
        # General validation
        if not provider.name:
            errors.append("Provider name is required")
        if not provider.issuer:
            errors.append("Issuer URL is required")
        
        return len(errors) == 0, errors
    
    def register_azure_ad(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        name: str = "Azure AD",
    ) -> IdentityProvider:
        """Convenience method to register Azure AD."""
        issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        metadata_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
        
        return self.register_provider(
            name=name,
            provider_type=IdentityProviderType.AZURE_AD,
            sso_provider=SSOProvider.AZURE_AD,
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            metadata_url=metadata_url,
            oidc_discovery_url=metadata_url,
        )
    
    def register_okta(
        self,
        domain: str,
        client_id: str,
        client_secret: str,
        name: str = "Okta",
    ) -> IdentityProvider:
        """Convenience method to register Okta."""
        issuer = f"https://{domain}/oauth2/default"
        metadata_url = f"https://{domain}/.well-known/openid-configuration"
        
        return self.register_provider(
            name=name,
            provider_type=IdentityProviderType.OKTA,
            sso_provider=SSOProvider.OKTA,
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            metadata_url=metadata_url,
            oidc_discovery_url=metadata_url,
        )
    
    def register_auth0(
        self,
        domain: str,
        client_id: str,
        client_secret: str,
        name: str = "Auth0",
    ) -> IdentityProvider:
        """Convenience method to register Auth0."""
        issuer = f"https://{domain}/"
        metadata_url = f"https://{domain}/.well-known/openid-configuration"
        
        return self.register_provider(
            name=name,
            provider_type=IdentityProviderType.AUTH0,
            sso_provider=SSOProvider.AUTH0,
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            metadata_url=metadata_url,
            oidc_discovery_url=metadata_url,
        )
    
    def register_google(
        self,
        client_id: str,
        client_secret: str,
        name: str = "Google Workspace",
    ) -> IdentityProvider:
        """Convenience method to register Google Workspace."""
        issuer = "https://accounts.google.com"
        metadata_url = "https://accounts.google.com/.well-known/openid-configuration"
        
        return self.register_provider(
            name=name,
            provider_type=IdentityProviderType.GOOGLE,
            sso_provider=SSOProvider.GOOGLE_WORKSPACE,
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            metadata_url=metadata_url,
            oidc_discovery_url=metadata_url,
        )
    
    def register_keycloak(
        self,
        realm: str,
        auth_server_url: str,
        client_id: str,
        client_secret: str,
        name: str = "Keycloak",
    ) -> IdentityProvider:
        """Convenience method to register Keycloak."""
        issuer = f"{auth_server_url.rstrip('/')}/realms/{realm}"
        metadata_url = f"{auth_server_url.rstrip('/')}/realms/{realm}/.well-known/openid-configuration"
        
        return self.register_provider(
            name=name,
            provider_type=IdentityProviderType.KEYCLOAK,
            sso_provider=SSOProvider.KEYCLOAK,
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            metadata_url=metadata_url,
            oidc_discovery_url=metadata_url,
        )