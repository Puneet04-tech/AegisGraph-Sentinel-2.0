"""SAML 2.0 Provider"""
import base64, secrets, uuid, xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode
from .models import IdentityProvider, AuthenticationRequest, AuthenticationResponse, FederatedUser, FederationSession, TokenType, SessionState
from .store import IdentityFederationStore

NAMESPACES = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol", "saml": "urn:oasis:names:tc:SAML:2.0:assertion", "ds": "http://www.w3.org/2000/09/xmldsig#"}

class SAMLProvider:
    def __init__(self, store: IdentityFederationStore, sp_id: str):
        self._store = store; self._sp_id = sp_id
        self._sp_sso_url = "https://aegisgraph.example.com/api/v1/identity/saml/acs"
    
    def initiate_login(self, provider_id: str, return_url: Optional[str] = None, force_authn: bool = False) -> AuthenticationResponse:
        provider = self._store.get_provider(provider_id)
        if not provider: return AuthenticationResponse(success=False, error="provider_not_found", error_description="Provider not found")
        if not provider.enabled: return AuthenticationResponse(success=False, error="provider_disabled", error_description="Provider is disabled")
        if not provider.saml_sso_url: return AuthenticationResponse(success=False, error="no_saml_support", error_description="Provider does not support SAML")
        
        request_id = f"_{secrets.token_hex(16)}"
        issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        authn_request = f'''<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" Destination="{provider.saml_sso_url}"
    AssertionConsumerServiceURL="{self._sp_sso_url}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    {'ForceAuthn="true"' if force_authn else ''}>
    <saml:Issuer>{self._sp_id}</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>'''
        
        encoded_request = base64.b64encode(authn_request.encode()).decode()
        relay_state = base64.b64encode(f"{request_id}:{return_url or ''}".encode()).decode()
        redirect_url = f"{provider.saml_sso_url}?{urlencode({'SAMLRequest': encoded_request, 'RelayState': relay_state})}"
        
        return AuthenticationResponse(success=True, redirect_url=redirect_url, provider_id=provider_id, authentication_method="saml", metadata={"request_id": request_id})
    
    def process_response(self, saml_response: str, relay_state: Optional[str] = None) -> AuthenticationResponse:
        try:
            response_xml = base64.b64decode(saml_response).decode()
            root = ET.fromstring(response_xml)
            status = root.find(".//samlp:StatusCode", NAMESPACES)
            status_code = status.get("Value", "urn:oasis:names:tc:SAML:2.0:status:Unknown") if status is not None else "urn:oasis:names:tc:SAML:2.0:status:Unknown"
            
            if status_code != "urn:oasis:names:tc:SAML:2.0:status:Success":
                return AuthenticationResponse(success=False, error="saml_error", error_description=f"SAML auth failed: {status_code}")
            
            assertion = root.find(".//saml:Assertion", NAMESPACES)
            if not assertion: return AuthenticationResponse(success=False, error="no_assertion", error_description="No SAML assertion found")
            
            user_info = self._extract_user_info(assertion)
            name_id = assertion.find("saml:Subject/saml:NameID", NAMESPACES)
            provider_user_id = name_id.text if name_id is not None else ""
            
            issuer_elem = assertion.find("saml:Issuer", NAMESPACES)
            issuer = issuer_elem.text if issuer_elem is not None else ""
            
            provider = None
            for p in self._store.list_providers():
                if p.issuer == issuer or issuer in p.issuer:
                    provider = p; break
            if not provider: return AuthenticationResponse(success=False, error="provider_not_found", error_description="IdP not found")
            
            existing = self._store.get_user_by_provider(provider.id, provider_user_id)
            if existing:
                existing.last_login = datetime.utcnow(); existing.profile_data = user_info
                self._store.update_user(existing); user = existing
            else:
                user_id = str(uuid.uuid4())
                user = FederatedUser(id=user_id, provider_id=provider.id, provider_user_id=provider_user_id,
                                     email=user_info.get("email", f"{provider_user_id}@{provider.name.lower()}.local"),
                                     display_name=user_info.get("display_name"), first_name=user_info.get("first_name"),
                                     last_name=user_info.get("last_name"), groups=user_info.get("groups", []),
                                     profile_data=user_info, last_login=datetime.utcnow())
                self._store.register_user(user)
            
            session_index = None
            authn_stmt = assertion.find("saml:AuthnStatement", NAMESPACES)
            if authn_stmt is not None: session_index = authn_stmt.get("SessionIndex")
            
            session_id = f"saml_{secrets.token_hex(24)}"
            session = FederationSession(id=session_id, user_id=user.id, provider_id=provider.id, state=SessionState.ACTIVE,
                                       session_index=session_index, expires_at=datetime.utcnow() + timedelta(hours=1),
                                       authentication_method="saml")
            self._store.create_session(session)
            
            return AuthenticationResponse(success=True, user=user, session=session, provider_id=provider.id, authentication_method="saml")
        except Exception as e:
            return AuthenticationResponse(success=False, error="processing_error", error_description=str(e))
    
    def _extract_user_info(self, assertion: ET.Element) -> dict:
        user_info = {}
        name_id = assertion.find("saml:Subject/saml:NameID", NAMESPACES)
        if name_id is not None:
            user_info["provider_user_id"] = name_id.text; user_info["email"] = name_id.text
        for attr in assertion.findall("saml:AttributeStatement/saml:Attribute", NAMESPACES):
            name = attr.get("Name", "")
            value_elem = attr.find("saml:AttributeValue", NAMESPACES)
            if value_elem is not None and value_elem.text: user_info[name] = value_elem.text
        return user_info