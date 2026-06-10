"""
SAML 2.0 Provider

Implements SAML 2.0 authentication flow.
"""

import base64
import hashlib
import secrets
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode, parse_qs, urlparse

from .models import (
    IdentityProvider,
    AuthenticationRequest,
    AuthenticationResponse,
    FederatedUser,
    FederationSession,
    TokenType,
    SessionState,
)
from .store import IdentityFederationStore


class SAMLProvider:
    """
    SAML 2.0 Identity Provider implementation.
    
    Supports SAML 2.0 authentication, assertion validation,
    and attribute mapping.
    """
    
    # SAML Namespaces
    NAMESPACES = {
        "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    }
    
    def __init__(self, store: IdentityFederationStore, service_provider_id: str):
        self._store = store
        self._sp_id = service_provider_id
        self._sp_sso_url = f"https://aegisgraph.example.com/api/v1/identity/saml/acs"
        self._sp_slo_url = f"https://aegisgraph.example.com/api/v1/identity/saml/slo"
    
    def initiate_login(
        self,
        provider_id: str,
        return_url: Optional[str] = None,
        force_authn: bool = False,
    ) -> AuthenticationResponse:
        """
        Initiate SAML login flow.
        
        Args:
            provider_id: Identity Provider ID
            return_url: URL to redirect after authentication
            force_authn: Force re-authentication
        
        Returns:
            AuthenticationResponse with SAML AuthnRequest
        """
        provider = self._store.get_provider(provider_id)
        if not provider:
            return AuthenticationResponse(
                success=False,
                error="provider_not_found",
                error_description=f"Identity provider {provider_id} not found",
            )
        
        if not provider.enabled:
            return AuthenticationResponse(
                success=False,
                error="provider_disabled",
                error_description="Identity provider is disabled",
            )
        
        provider_type = provider.provider_type.value if hasattr(provider.provider_type, 'value') else provider.provider_type
        if provider_type not in ["saml", "okta", "azure_ad", "keycloak"] and not provider.saml_sso_url:
            return AuthenticationResponse(
                success=False,
                error="invalid_provider_type",
                error_description="Provider does not support SAML",
            )
        
        # Generate request ID
        request_id = f"_{secrets.token_hex(16)}"
        
        # Generate SAML AuthnRequest
        authn_request = self._create_authn_request(
            provider=provider,
            request_id=request_id,
            return_url=return_url,
            force_authn=force_authn,
        )
        
        # Encode and redirect
        encoded_request = base64.b64encode(authn_request.encode()).decode()
        
        # Create relay state
        relay_state = self._create_relay_state(request_id, return_url)
        
        # Build redirect URL
        redirect_url = f"{provider.saml_sso_url}?{urlencode({'SAMLRequest': encoded_request, 'RelayState': relay_state})}"
        
        return AuthenticationResponse(
            success=True,
            redirect_url=redirect_url,
            provider_id=provider_id,
            authentication_method="saml",
            metadata={"request_id": request_id},
        )
    
    def _create_authn_request(
        self,
        provider: IdentityProvider,
        request_id: str,
        return_url: Optional[str],
        force_authn: bool,
    ) -> str:
        """Create SAML AuthnRequest XML."""
        issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        authn_request = f'''<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{provider.saml_sso_url}"
    AssertionConsumerServiceURL="{self._sp_sso_url}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    {'ForceAuthn="true"' if force_authn else ''}>
    <saml:Issuer>{self._sp_id}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        AllowCreate="true"/>
</samlp:AuthnRequest>'''
        
        return authn_request
    
    def _create_relay_state(self, request_id: str, return_url: Optional[str]) -> str:
        """Create and store relay state."""
        relay_data = f"{request_id}:{return_url or ''}"
        return base64.b64encode(relay_data.encode()).decode()
    
    def process_response(
        self,
        saml_response: str,
        relay_state: Optional[str] = None,
    ) -> AuthenticationResponse:
        """
        Process SAML Response from IdP.
        
        Args:
            saml_response: Base64-encoded SAML Response
            relay_state: Relay state from login request
        
        Returns:
            AuthenticationResponse with user information
        """
        try:
            # Decode response
            response_xml = base64.b64decode(saml_response).decode()
            
            # Parse XML
            root = ET.fromstring(response_xml)
            
            # Validate response status
            status = self._get_status(root)
            if status != "urn:oasis:names:tc:SAML:2.0:status:Success":
                return AuthenticationResponse(
                    success=False,
                    error="saml_error",
                    error_description=f"SAML authentication failed: {status}",
                )
            
            # Extract assertion
            assertion = root.find(".//saml:Assertion", self.NAMESPACES)
            if assertion is None:
                return AuthenticationResponse(
                    success=False,
                    error="no_assertion",
                    error_description="No SAML assertion found",
                )
            
            # Validate assertion
            is_valid, error = self._validate_assertion(assertion)
            if not is_valid:
                return AuthenticationResponse(
                    success=False,
                    error="assertion_invalid",
                    error_description=error,
                )
            
            # Extract user information
            user_info = self._extract_user_info(assertion)
            
            # Get provider ID from issuer
            issuer = self._get_issuer(assertion)
            provider = self._get_provider_by_issuer(issuer)
            if not provider:
                return AuthenticationResponse(
                    success=False,
                    error="provider_not_found",
                    error_description="Identity provider not found for issuer",
                )
            
            # Create or update federated user
            user = self._get_or_create_user(provider, user_info)
            
            # Create session
            session = self._create_session(user, provider, assertion)
            
            return AuthenticationResponse(
                success=True,
                user=user,
                session=session,
                provider_id=provider.id,
                authentication_method="saml",
            )
            
        except Exception as e:
            return AuthenticationResponse(
                success=False,
                error="processing_error",
                error_description=f"Error processing SAML response: {str(e)}",
            )
    
    def _get_status(self, root: ET.Element) -> str:
        """Extract SAML status code."""
        status_code = root.find(".//samlp:StatusCode", self.NAMESPACES)
        if status_code is not None:
            return status_code.get("Value", "urn:oasis:names:tc:SAML:2.0:status:Unknown")
        return "urn:oasis:names:tc:SAML:2.0:status:Unknown"
    
    def _validate_assertion(self, assertion: ET.Element) -> tuple[bool, Optional[str]]:
        """Validate SAML assertion."""
        # Check conditions
        conditions = assertion.find("saml:Conditions", self.NAMESPACES)
        if conditions is not None:
            # Check not_before
            not_before = conditions.get("NotBefore")
            if not_before:
                not_before_time = datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%SZ")
                if datetime.utcnow() < not_before_time:
                    return False, "Assertion not yet valid"
            
            # Check not_on_or_after
            not_on_or_after = conditions.get("NotOnOrAfter")
            if not_on_or_after:
                not_after_time = datetime.strptime(not_on_or_after, "%Y-%m-%dT%H:%M:%SZ")
                if datetime.utcnow() >= not_after_time:
                    return False, "Assertion expired"
        
        return True, None
    
    def _extract_user_info(self, assertion: ET.Element) -> dict:
        """Extract user information from SAML assertion."""
        user_info = {}
        
        # Extract NameID
        name_id = assertion.find("saml:Subject/saml:NameID", self.NAMESPACES)
        if name_id is not None:
            user_info["provider_user_id"] = name_id.text
            user_info["email"] = name_id.text
        
        # Extract attributes
        for attr in assertion.findall("saml:AttributeStatement/saml:Attribute", self.NAMESPACES):
            name = attr.get("Name", "")
            value_elem = attr.find("saml:AttributeValue", self.NAMESPACES)
            if value_elem is not None and value_elem.text:
                user_info[name] = value_elem.text
        
        return user_info
    
    def _get_provider_by_issuer(self, issuer: str) -> Optional[IdentityProvider]:
        """Get provider by issuer URL."""
        providers = self._store.list_providers()
        for provider in providers:
            if provider.issuer == issuer or issuer in provider.issuer:
                return provider
        return None
    
    def _get_or_create_user(
        self, provider: IdentityProvider, user_info: dict
    ) -> FederatedUser:
        """Get or create federated user."""
        provider_user_id = user_info.get("provider_user_id", "")
        
        # Check if user exists
        existing_user = self._store.get_user_by_provider(provider.id, provider_user_id)
        if existing_user:
            # Update user info
            existing_user.last_login = datetime.utcnow()
            existing_user.profile_data = user_info
            self._store.update_user(existing_user)
            return existing_user
        
        # Create new user
        user_id = str(uuid.uuid4())
        user = FederatedUser(
            id=user_id,
            provider_id=provider.id,
            provider_user_id=provider_user_id,
            email=user_info.get("email", f"{provider_user_id}@{provider.name.lower()}.local"),
            display_name=user_info.get("display_name") or user_info.get("name"),
            first_name=user_info.get("first_name") or user_info.get("given_name"),
            last_name=user_info.get("last_name") or user_info.get("surname"),
            groups=user_info.get("groups", []),
            profile_data=user_info,
            last_login=datetime.utcnow(),
        )
        
        self._store.register_user(user)
        return user
    
    def _create_session(
        self,
        user: FederatedUser,
        provider: IdentityProvider,
        assertion: ET.Element,
    ) -> FederationSession:
        """Create federation session from SAML assertion."""
        # Extract session index
        session_index = None
        authn_statement = assertion.find("saml:AuthnStatement", self.NAMESPACES)
        if authn_statement is not None:
            session_index = authn_statement.get("SessionIndex")
        
        session_id = f"saml_{secrets.token_hex(24)}"
        expires_at = datetime.utcnow() + timedelta(hours=self._store._session_ttl)
        
        session = FederationSession(
            id=session_id,
            user_id=user.id,
            provider_id=provider.id,
            state=SessionState.ACTIVE,
            session_index=session_index,
            expires_at=expires_at,
            authentication_method="saml",
        )
        
        self._store.create_session(session)
        return session
    
    def process_logout_request(
        self,
        saml_logout_request: str,
    ) -> AuthenticationResponse:
        """Process SAML LogoutRequest."""
        try:
            request_xml = base64.b64decode(saml_logout_request).decode()
            root = ET.fromstring(request_xml)
            
            # Extract NameID and SessionIndex
            name_id = root.find(".//saml:NameID", self.NAMESPACES)
            session_index = root.find(".//samlp:SessionIndex", self.NAMESPACES)
            
            if name_id is not None:
                # Find and revoke user sessions
                users = self._store.list_users_by_provider("")
                for user in users:
                    if user.provider_user_id == name_id.text:
                        self._store.revoke_user_sessions(user.id)
                        break
            
            return AuthenticationResponse(success=True)
            
        except Exception as e:
            return AuthenticationResponse(
                success=False,
                error="logout_error",
                error_description=str(e),
            )
    
    def generate_logout_request(
        self,
        user_id: str,
        provider_id: str,
        return_url: Optional[str] = None,
    ) -> Optional[str]:
        """Generate SAML LogoutRequest."""
        provider = self._store.get_provider(provider_id)
        if not provider or not provider.saml_slo_url:
            return None
        
        # Get user sessions
        sessions = self._store.get_session_by_user(user_id)
        session_index = sessions[0].session_index if sessions else None
        
        request_id = f"_{secrets.token_hex(16)}"
        issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Get user for NameID
        user = self._store.get_user(user_id)
        name_id = user.provider_user_id if user else "unknown"
        
        logout_request = f'''<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{provider.saml_slo_url}">
    <saml:Issuer>{self._sp_id}</saml:Issuer>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
    {f'<samlp:SessionIndex>{session_index}</samlp:SessionIndex>' if session_index else ''}
</samlp:LogoutRequest>'''
        
        return base64.b64encode(logout_request.encode()).decode()