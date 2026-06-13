"""
Federation Manager

Orchestrates identity federation across multiple providers.
"""

import hashlib
import secrets
import uuid
from datetime import datetime
from typing import Optional

from .models import (
    IdentityProvider,
    AuthenticationRequest,
    AuthenticationResponse,
    FederatedUser,
    FederationSession,
)
from .store import IdentityFederationStore
from .providers import IdentityProviderRegistry
from .saml_provider import SAMLProvider
from .oidc_provider import OIDCProvider
from .oauth_provider import OAuthProvider


class FederationManager:
    """
    Federation Manager orchestrates authentication across
    multiple identity providers.
    """
    
    def __init__(self, store: IdentityFederationStore, sp_id: str, issuer: str):
        self._store = store
        self._sp_id = sp_id
        self._issuer = issuer
        
        # Initialize components
        self._registry = IdentityProviderRegistry(store)
        self._saml = SAMLProvider(store, sp_id)
        self._oidc = OIDCProvider(store, issuer)
        self._oauth = OAuthProvider(store, issuer)
        
        # Pending authentication requests
        self._pending_auths: dict[str, dict] = {}
    
    @property
    def registry(self) -> IdentityProviderRegistry:
        """Get the identity provider registry."""
        return self._registry
    
    def authenticate(
        self,
        request: AuthenticationRequest,
    ) -> AuthenticationResponse:
        """
        Initiate authentication with specified provider.
        
        Args:
            request: Authentication request
        
        Returns:
            AuthenticationResponse with redirect URL or error
        """
        provider = self._store.get_provider(request.provider_id)
        if not provider:
            return AuthenticationResponse(
                success=False,
                error="provider_not_found",
                error_description=f"Provider {request.provider_id} not found",
            )
        
        if not provider.enabled:
            return AuthenticationResponse(
                success=False,
                error="provider_disabled",
                error_description="Identity provider is disabled",
            )
        
        # Route to appropriate provider handler
        provider_type = provider.provider_type.value if hasattr(provider.provider_type, 'value') else provider.provider_type
        
        if provider_type == "saml":
            return self._saml.initiate_login(
                provider_id=request.provider_id,
                return_url=request.return_url,
                force_authn=request.saml_force_authn,
            )
        
        elif provider_type in ["oidc", "azure_ad", "okta", "auth0", "google", "keycloak"]:
            return self._oidc.initiate_login(
                provider_id=request.provider_id,
                return_url=request.return_url,
                prompt=request.oidc_prompt,
                max_age=request.oidc_max_age,
                acr_values=request.oidc_acr_values,
            )
        
        elif provider_type == "oauth2":
            return AuthenticationResponse(
                success=False,
                error="oauth2_redirect",
                error_description="OAuth2 requires authorization endpoint",
                redirect_url=f"{provider.issuer}/authorize",
            )
        
        return AuthenticationResponse(
            success=False,
            error="unsupported_provider",
            error_description=f"Provider type {provider_type} not supported",
        )
    
    def handle_callback(
        self,
        provider_id: str,
        protocol: str,
        **kwargs,
    ) -> AuthenticationResponse:
        """
        Handle authentication callback from IdP.
        
        Args:
            provider_id: Identity Provider ID
            protocol: Protocol used (saml, oidc, oauth)
            **kwargs: Protocol-specific callback data
        
        Returns:
            AuthenticationResponse with user/session
        """
        if protocol == "saml":
            return self._saml.process_response(
                saml_response=kwargs.get("SAMLResponse", ""),
                relay_state=kwargs.get("RelayState"),
            )
        
        elif protocol == "oidc":
            code = kwargs.get("code", "")
            state = kwargs.get("state", "")
            
            # Get pending auth for state validation
            pending = self._pending_auths.pop(state, {})
            expected_state = pending.get("state", "")
            
            return self._oidc.exchange_code(
                provider_id=provider_id,
                code=code,
                expected_state=expected_state,
                provided_state=state,
            )
        
        elif protocol == "oauth":
            code = kwargs.get("code", "")
            state = kwargs.get("state", "")
            
            return self._oauth.authorize(
                client_id=kwargs.get("client_id", ""),
                redirect_uri=kwargs.get("redirect_uri", ""),
                response_type="code",
                scope=kwargs.get("scope", "openid profile email"),
                state=state,
            )
        
        return AuthenticationResponse(
            success=False,
            error="unknown_protocol",
            error_description=f"Unknown protocol: {protocol}",
        )
    
    def process_token(
        self,
        provider_id: str,
        token: str,
        protocol: str = "oidc",
        nonce: Optional[str] = None,
    ) -> AuthenticationResponse:
        """
        Process token from IdP callback.
        
        Args:
            provider_id: Identity Provider ID
            token: Token to process
            protocol: Protocol used
            nonce: Expected nonce (for OIDC)
        
        Returns:
            AuthenticationResponse with user/session
        """
        if protocol == "oidc":
            return self._oidc.process_id_token(
                provider_id=provider_id,
                id_token=token,
                expected_nonce=nonce,
            )
        
        return AuthenticationResponse(
            success=False,
            error="unsupported_protocol",
            error_description=f"Token processing not supported for {protocol}",
        )
    
    def initiate_sso(
        self,
        user_id: str,
        provider_id: str,
        target_url: Optional[str] = None,
    ) -> AuthenticationResponse:
        """
        Initiate Single Sign-On for existing user.
        
        Args:
            user_id: User ID
            provider_id: Provider to use for SSO
            target_url: Target application URL
        
        Returns:
            AuthenticationResponse with SSO URL
        """
        user = self._store.get_user(user_id)
        if not user:
            return AuthenticationResponse(
                success=False,
                error="user_not_found",
                error_description="User not found",
            )
        
        provider = self._store.get_provider(provider_id)
        if not provider:
            return AuthenticationResponse(
                success=False,
                error="provider_not_found",
                error_description="Provider not found",
            )
        
        # Check if user is linked to this provider
        if user.provider_id != provider_id:
            return AuthenticationResponse(
                success=False,
                error="user_not_linked",
                error_description="User is not linked to this identity provider",
            )
        
        # Create authentication request
        request = AuthenticationRequest(
            provider_id=provider_id,
            return_url=target_url,
        )
        
        return self.authenticate(request)
    
    def link_provider(
        self,
        user_id: str,
        provider_id: str,
        provider_user_id: str,
        provider_token: Optional[str] = None,
    ) -> AuthenticationResponse:
        """
        Link an identity provider to an existing user.
        
        Args:
            user_id: Local user ID
            provider_id: Provider to link
            provider_user_id: User ID from provider
            provider_token: Optional access token from provider
        
        Returns:
            AuthenticationResponse with result
        """
        user = self._store.get_user(user_id)
        if not user:
            return AuthenticationResponse(
                success=False,
                error="user_not_found",
                error_description="User not found",
            )
        
        provider = self._store.get_provider(provider_id)
        if not provider:
            return AuthenticationResponse(
                success=False,
                error="provider_not_found",
                error_description="Provider not found",
            )
        
        # Check if already linked
        existing = self._store.get_user_by_provider(provider_id, provider_user_id)
        if existing and existing.id != user_id:
            return AuthenticationResponse(
                success=False,
                error="already_linked",
                error_description="This provider account is already linked to another user",
            )
        
        # Update user with provider link
        user.provider_id = provider_id
        user.provider_user_id = provider_user_id
        user.updated_at = datetime.utcnow()
        
        if provider_token:
            user.profile_data["provider_token"] = provider_token
        
        self._store.update_user(user)
        
        return AuthenticationResponse(
            success=True,
            user=user,
            provider_id=provider_id,
            authentication_method="link",
        )
    
    def unlink_provider(
        self,
        user_id: str,
        provider_id: str,
    ) -> AuthenticationResponse:
        """
        Unlink an identity provider from a user.
        
        Args:
            user_id: Local user ID
            provider_id: Provider to unlink
        
        Returns:
            AuthenticationResponse with result
        """
        user = self._store.get_user(user_id)
        if not user:
            return AuthenticationResponse(
                success=False,
                error="user_not_found",
                error_description="User not found",
            )
        
        if user.provider_id != provider_id:
            return AuthenticationResponse(
                success=False,
                error="not_linked",
                error_description="User is not linked to this provider",
            )
        
        # Revoke user sessions
        self._store.revoke_user_sessions(user_id)
        
        # Clear provider link
        user.provider_id = ""
        user.provider_user_id = ""
        user.updated_at = datetime.utcnow()
        
        self._store.update_user(user)
        
        return AuthenticationResponse(
            success=True,
            user=user,
            provider_id=provider_id,
            authentication_method="unlink",
        )
    
    def get_federated_identities(self, user_id: str) -> list[dict]:
        """
        Get all federated identities for a user.
        
        Args:
            user_id: Local user ID
        
        Returns:
            List of linked identity provider info
        """
        user = self._store.get_user(user_id)
        if not user:
            return []
        
        identities = []
        
        # Current provider
        if user.provider_id:
            provider = self._store.get_provider(user.provider_id)
            if provider:
                identities.append({
                    "provider_id": provider.id,
                    "provider_name": provider.name,
                    "provider_type": provider.provider_type.value,
                    "provider_user_id": user.provider_user_id,
                    "linked": True,
                })
        
        return identities
    
    def validate_session(self, session_id: str) -> Optional[FederationSession]:
        """
        Validate a federation session.
        
        Args:
            session_id: Session ID
        
        Returns:
            Session if valid, None otherwise
        """
        return self._store.get_session(session_id)
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke a federation session."""
        return self._store.revoke_session(session_id)
    
    def revoke_all_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user."""
        return self._store.revoke_user_sessions(user_id)