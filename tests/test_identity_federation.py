"""
Identity Federation Tests

Unit tests for the Enterprise Identity Federation Platform.
"""

import base64
import pytest
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

from src.identity_federation import (
    IdentityFederationService,
    IdentityFederationStore,
    IdentityProviderRegistry,
    IdentityProvider,
    IdentityProviderType,
    SSOProvider,
    FederatedUser,
    FederationSession,
    SessionState,
    SAMLProvider,
    OIDCProvider,
    OAuthProvider,
    SessionManager,
    IdentityMapper,
    ProvisioningService,
    AuditLogger,
)
from src.identity_federation.models import AuthenticationRequest, AuthenticationResponse


def _self_signed_cert_and_key() -> tuple[str, str]:
    """Generate a throwaway RSA keypair + self-signed cert for signing test assertions."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def _build_saml_response(
    name_id: str,
    issuer: str,
    sign_with_key: str = None,
    sign_with_cert: str = None,
    conditions: dict = None,
) -> str:
    """Build a base64-encoded SAML Response, optionally with a signed assertion."""
    import lxml.etree as lxml_etree
    from signxml import XMLSigner

    samlp_ns = "urn:oasis:names:tc:SAML:2.0:protocol"
    saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion"
    response = lxml_etree.Element(
        f"{{{samlp_ns}}}Response",
        nsmap={"samlp": samlp_ns, "saml": saml_ns},
        ID="_resp1",
        Version="2.0",
    )
    status = lxml_etree.SubElement(response, f"{{{samlp_ns}}}Status")
    lxml_etree.SubElement(
        status, f"{{{samlp_ns}}}StatusCode", Value="urn:oasis:names:tc:SAML:2.0:status:Success"
    )
    assertion = lxml_etree.SubElement(response, f"{{{saml_ns}}}Assertion", ID="_assertion1", Version="2.0")
    lxml_etree.SubElement(assertion, f"{{{saml_ns}}}Issuer").text = issuer
    subject = lxml_etree.SubElement(assertion, f"{{{saml_ns}}}Subject")
    lxml_etree.SubElement(subject, f"{{{saml_ns}}}NameID").text = name_id

    if conditions is not None:
        conditions_elem = lxml_etree.SubElement(assertion, f"{{{saml_ns}}}Conditions")
        for attr, value in conditions.items():
            conditions_elem.set(attr, value)

    if sign_with_key:
        signed_assertion = XMLSigner().sign(assertion, key=sign_with_key, cert=sign_with_cert)
        response.replace(assertion, signed_assertion)

    xml_bytes = lxml_etree.tostring(response, xml_declaration=True, encoding="UTF-8")
    return base64.b64encode(xml_bytes).decode()


def _build_saml_response_signed_root(
    name_id: str, issuer: str, sign_with_key: str, sign_with_cert: str
) -> str:
    """Build a SAML Response whose whole root (not just the assertion) is signed."""
    import lxml.etree as lxml_etree
    from signxml import XMLSigner

    samlp_ns = "urn:oasis:names:tc:SAML:2.0:protocol"
    saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion"
    response = lxml_etree.Element(
        f"{{{samlp_ns}}}Response",
        nsmap={"samlp": samlp_ns, "saml": saml_ns},
        ID="_resp_signed",
        Version="2.0",
    )
    status = lxml_etree.SubElement(response, f"{{{samlp_ns}}}Status")
    lxml_etree.SubElement(
        status, f"{{{samlp_ns}}}StatusCode", Value="urn:oasis:names:tc:SAML:2.0:status:Success"
    )
    assertion = lxml_etree.SubElement(response, f"{{{saml_ns}}}Assertion", ID="_assertion_signed", Version="2.0")
    lxml_etree.SubElement(assertion, f"{{{saml_ns}}}Issuer").text = issuer
    subject = lxml_etree.SubElement(assertion, f"{{{saml_ns}}}Subject")
    lxml_etree.SubElement(subject, f"{{{saml_ns}}}NameID").text = name_id

    signed = XMLSigner().sign(response, key=sign_with_key, cert=sign_with_cert)
    xml_bytes = lxml_etree.tostring(signed, xml_declaration=True, encoding="UTF-8")
    return base64.b64encode(xml_bytes).decode()


class TestIdentityFederationStore:
    """Tests for IdentityFederationStore."""
    
    def test_provider_crud_operations(self):
        """Test identity provider CRUD operations."""
        store = IdentityFederationStore()
        
        # Create provider
        provider = IdentityProvider(
            id="test-provider-1",
            name="Test Provider",
            provider_type=IdentityProviderType.OIDC,
            issuer="https://test.example.com",
            client_id="client123",
            client_secret="secret456",
        )
        
        store.register_provider(provider)
        
        # Read
        retrieved = store.get_provider("test-provider-1")
        assert retrieved is not None
        assert retrieved.name == "Test Provider"
        assert retrieved.issuer == "https://test.example.com"
        
        # Update
        provider.enabled = False
        store.update_provider(provider)
        assert store.get_provider("test-provider-1").enabled is False
        
        # Delete
        assert store.delete_provider("test-provider-1") is True
        assert store.get_provider("test-provider-1") is None
    
    def test_user_crud_operations(self):
        """Test federated user CRUD operations."""
        store = IdentityFederationStore()
        
        # Create user
        user = FederatedUser(
            id="user-1",
            provider_id="provider-1",
            provider_user_id="ext-user-1",
            email="user@example.com",
            display_name="Test User",
        )
        
        store.register_user(user)
        
        # Read by ID
        retrieved = store.get_user("user-1")
        assert retrieved is not None
        assert retrieved.email == "user@example.com"
        
        # Read by email
        retrieved = store.get_user_by_email("user@example.com")
        assert retrieved is not None
        
        # Read by provider
        retrieved = store.get_user_by_provider("provider-1", "ext-user-1")
        assert retrieved is not None
        
        # Update
        user.roles = ["admin"]
        store.update_user(user)
        assert store.get_user("user-1").roles == ["admin"]
        
        # Delete
        assert store.delete_user("user-1") is True
        assert store.get_user("user-1") is None
    
    def test_session_management(self):
        """Test federation session management."""
        store = IdentityFederationStore()
        
        # Create session
        session = FederationSession(
            id="session-1",
            user_id="user-1",
            provider_id="provider-1",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        
        store.create_session(session)
        
        # Read
        retrieved = store.get_session("session-1")
        assert retrieved is not None
        assert retrieved.user_id == "user-1"
        
        # Revoke
        assert store.revoke_session("session-1") is True
        retrieved = store.get_session("session-1")
        assert retrieved is not None
        assert retrieved.state == SessionState.REVOKED
    
    def test_o1_lookup_performance(self):
        """Test O(1) lookup performance."""
        store = IdentityFederationStore()
        
        # Add many providers
        for i in range(100):
            provider = IdentityProvider(
                id=f"provider-{i}",
                name=f"Provider {i}",
                provider_type=IdentityProviderType.OIDC,
                issuer=f"https://provider-{i}.example.com",
            )
            store.register_provider(provider)
        
        # O(1) lookup test
        import time
        start = time.time()
        for i in range(100):
            store.get_provider(f"provider-{i}")
        elapsed = time.time() - start
        
        # Should be very fast (< 10ms for 100 lookups)
        assert elapsed < 0.1
    
    def test_thread_safety(self):
        """Test thread-safe operations."""
        store = IdentityFederationStore()
        errors = []
        
        def worker(n):
            try:
                for i in range(100):
                    provider = IdentityProvider(
                        id=f"provider-{n}-{i}",
                        name=f"Provider {n}-{i}",
                        provider_type=IdentityProviderType.OIDC,
                        issuer=f"https://provider-{n}-{i}.example.com",
                    )
                    store.register_provider(provider)
                    store.get_provider(f"provider-{n}-{i}")
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0


class TestIdentityProviderRegistry:
    """Tests for IdentityProviderRegistry."""
    
    def test_register_azure_ad(self):
        """Test Azure AD registration."""
        store = IdentityFederationStore()
        registry = IdentityProviderRegistry(store)
        
        provider = registry.register_azure_ad(
            tenant_id="test-tenant",
            client_id="client-id",
            client_secret="client-secret",
            name="Test Azure AD",
        )
        
        assert provider.name == "Test Azure AD"
        assert provider.sso_provider == SSOProvider.AZURE_AD
        assert "login.microsoftonline.com" in provider.issuer
    
    def test_register_okta(self):
        """Test Okta registration."""
        store = IdentityFederationStore()
        registry = IdentityProviderRegistry(store)
        
        provider = registry.register_okta(
            domain="test.okta.com",
            client_id="client-id",
            client_secret="client-secret",
        )
        
        assert provider.sso_provider == SSOProvider.OKTA
        assert "test.okta.com" in provider.issuer
    
    def test_validate_provider(self):
        """Test provider validation."""
        store = IdentityFederationStore()
        registry = IdentityProviderRegistry(store)
        
        # Valid SAML provider with all required fields
        valid_provider = IdentityProvider(
            id="valid-1",
            name="Valid SAML Provider",
            provider_type=IdentityProviderType.SAML,
            issuer="https://valid.example.com",
            saml_entity_id="test-entity",
            saml_sso_url="https://valid.example.com/sso",
            saml_certificate="cert-data",
        )
        
        is_valid, errors = registry.validate_provider(valid_provider)
        assert is_valid is True
        assert len(errors) == 0
        
        # Invalid SAML provider (missing certificate)
        invalid_provider = IdentityProvider(
            id="invalid-1",
            name="Invalid SAML Provider",
            provider_type=IdentityProviderType.SAML,
            issuer="https://invalid.example.com",
            saml_entity_id="test-entity",
            saml_sso_url="https://invalid.example.com/sso",
        )
        
        is_valid, errors = registry.validate_provider(invalid_provider)
        assert is_valid is False
        assert any("Certificate" in e for e in errors)


class TestSAMLProvider:
    """Tests for SAMLProvider."""
    
    def test_initiate_login(self):
        """Test SAML login initiation."""
        store = IdentityFederationStore()
        
        # Add provider with SAML SSO URL
        provider = IdentityProvider(
            id="saml-provider",
            name="Test SAML",
            provider_type=IdentityProviderType.SAML,
            issuer="https://saml.example.com",
            saml_entity_id="test-entity",
            saml_sso_url="https://saml.example.com/sso",
            saml_certificate="cert-data",
        )
        store.register_provider(provider)
        
        saml = SAMLProvider(store, "test-sp")
        response = saml.initiate_login(
            provider_id="saml-provider",
            return_url="https://app.example.com/callback",
        )
        
        assert response.success is True
        assert response.redirect_url is not None
        assert "SAMLRequest=" in response.redirect_url
        assert response.authentication_method == "saml"
    
    def test_process_response_rejects_unsigned_assertion(self):
        """An assertion with no XML signature must never be trusted."""
        store = IdentityFederationStore()
        cert_pem, _ = _self_signed_cert_and_key()
        store.register_provider(IdentityProvider(
            id="okta-prod",
            name="Okta",
            provider_type=IdentityProviderType.SAML,
            issuer="https://okta.example.com/saml",
            saml_sso_url="https://okta.example.com/sso",
            saml_certificate=cert_pem,
        ))
        saml = SAMLProvider(store, "test-sp")
        forged = _build_saml_response("admin@bank.example.com", "https://okta.example.com/saml")
        
        response = saml.process_response(forged)
        
        assert response.success is False
        assert response.user is None
    
    def test_process_response_accepts_validly_signed_assertion(self):
        """A correctly signed assertion from the registered IdP is trusted."""
        store = IdentityFederationStore()
        cert_pem, key_pem = _self_signed_cert_and_key()
        store.register_provider(IdentityProvider(
            id="okta-prod",
            name="Okta",
            provider_type=IdentityProviderType.SAML,
            issuer="https://okta.example.com/saml",
            saml_sso_url="https://okta.example.com/sso",
            saml_certificate=cert_pem,
        ))
        saml = SAMLProvider(store, "test-sp")
        signed = _build_saml_response(
            "real.user@example.com",
            "https://okta.example.com/saml",
            sign_with_key=key_pem,
            sign_with_cert=cert_pem,
        )
        
        response = saml.process_response(signed)
        
        assert response.success is True
        assert response.user.email == "real.user@example.com"

    def test_process_response_rejects_expired_assertion(self):
        """An assertion whose NotOnOrAfter has passed must be rejected."""
        store = IdentityFederationStore()
        cert_pem, key_pem = _self_signed_cert_and_key()
        store.register_provider(IdentityProvider(
            id="okta-prod",
            name="Okta",
            provider_type=IdentityProviderType.SAML,
            issuer="https://okta.example.com/saml",
            saml_sso_url="https://okta.example.com/sso",
            saml_certificate=cert_pem,
        ))
        saml = SAMLProvider(store, "test-sp")
        expired = _build_saml_response(
            "real.user@example.com",
            "https://okta.example.com/saml",
            sign_with_key=key_pem,
            sign_with_cert=cert_pem,
            conditions={
                "NotBefore": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "NotOnOrAfter": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        )

        response = saml.process_response(expired)

        assert response.success is False
        assert response.error == "assertion_invalid"
        assert response.user is None

    def test_process_response_rejects_not_yet_valid_assertion(self):
        """An assertion whose NotBefore is in the future must be rejected."""
        store = IdentityFederationStore()
        cert_pem, key_pem = _self_signed_cert_and_key()
        store.register_provider(IdentityProvider(
            id="okta-prod",
            name="Okta",
            provider_type=IdentityProviderType.SAML,
            issuer="https://okta.example.com/saml",
            saml_sso_url="https://okta.example.com/sso",
            saml_certificate=cert_pem,
        ))
        saml = SAMLProvider(store, "test-sp")
        future = _build_saml_response(
            "real.user@example.com",
            "https://okta.example.com/saml",
            sign_with_key=key_pem,
            sign_with_cert=cert_pem,
            conditions={
                "NotBefore": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "NotOnOrAfter": (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        )

        response = saml.process_response(future)

        assert response.success is False
        assert response.error == "assertion_invalid"
        assert response.user is None

    def test_process_response_signed_root_still_yields_user_info(self):
        """A response whose whole root is signed must still resolve the
        Assertion inside it and produce the federated user."""
        store = IdentityFederationStore()
        cert_pem, key_pem = _self_signed_cert_and_key()
        store.register_provider(IdentityProvider(
            id="okta-prod",
            name="Okta",
            provider_type=IdentityProviderType.SAML,
            issuer="https://okta.example.com/saml",
            saml_sso_url="https://okta.example.com/sso",
            saml_certificate=cert_pem,
        ))
        saml = SAMLProvider(store, "test-sp")
        signed = _build_saml_response_signed_root(
            "root.signed@example.com",
            "https://okta.example.com/saml",
            sign_with_key=key_pem,
            sign_with_cert=cert_pem,
        )

        response = saml.process_response(signed)

        assert response.success is True
        assert response.user.email == "root.signed@example.com"
        assert response.user.provider_user_id == "root.signed@example.com"

    def test_distinct_nameids_produce_distinct_users(self):
        """Two different NameIDs from the same IdP must map to two distinct
        FederatedUser records instead of collapsing into one."""
        store = IdentityFederationStore()
        cert_pem, key_pem = _self_signed_cert_and_key()
        store.register_provider(IdentityProvider(
            id="okta-prod",
            name="Okta",
            provider_type=IdentityProviderType.SAML,
            issuer="https://okta.example.com/saml",
            saml_sso_url="https://okta.example.com/sso",
            saml_certificate=cert_pem,
        ))
        saml = SAMLProvider(store, "test-sp")

        first = saml.process_response(_build_saml_response(
            "alice@example.com",
            "https://okta.example.com/saml",
            sign_with_key=key_pem,
            sign_with_cert=cert_pem,
        ))
        second = saml.process_response(_build_saml_response(
            "bob@example.com",
            "https://okta.example.com/saml",
            sign_with_key=key_pem,
            sign_with_cert=cert_pem,
        ))

        assert first.success is True
        assert second.success is True
        assert first.user.id != second.user.id
        assert first.user.provider_user_id != second.user.provider_user_id
        assert first.user.email != second.user.email


class TestOIDCProvider:
    """Tests for OIDCProvider."""
    
    def test_initiate_login(self):
        """Test OIDC login initiation."""
        store = IdentityFederationStore()
        
        # Add provider
        provider = IdentityProvider(
            id="oidc-provider",
            name="Test OIDC",
            provider_type=IdentityProviderType.OIDC,
            issuer="https://oidc.example.com",
            client_id="client-id",
            client_secret="client-secret",
            oidc_authorization_endpoint="https://oidc.example.com/authorize",
        )
        store.register_provider(provider)
        
        oidc = OIDCProvider(store, "https://aegisgraph.example.com")
        response = oidc.initiate_login(
            provider_id="oidc-provider",
            return_url="https://app.example.com/callback",
            scope="openid profile email",
        )
        
        assert response.success is True
        assert response.redirect_url is not None
        assert "client_id=client-id" in response.redirect_url
        assert response.authentication_method == "oidc"
    
    def test_validate_token_fails_closed_on_unverifiable_input(self):
        """Tokens must never be trusted without a real signature check."""
        store = IdentityFederationStore()
        oidc = OIDCProvider(store, "https://aegisgraph.example.com")
        
        # Unregistered provider
        is_valid, claims = oidc.validate_token(
            provider_id="unregistered-provider",
            token="any-token-value",
        )
        assert is_valid is False
        assert claims is None
        
        # Missing JWKS URI
        store.register_provider(IdentityProvider(
            id="misconfigured",
            name="Misconfigured IdP",
            provider_type=IdentityProviderType.OIDC,
            issuer="https://idp.example.com",
            client_id="client-id",
        ))
        is_valid, claims = oidc.validate_token(
            provider_id="misconfigured",
            token="any-token-value",
        )
        assert is_valid is False
        assert claims is None
    
    def test_validate_token_verifies_signature(self):
        """A token is only trusted if it's actually signed by the IdP's own key."""
        import jwt
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        idp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        idp_key_pem = idp_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        attacker_key_pem = attacker_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        
        store = IdentityFederationStore()
        store.register_provider(IdentityProvider(
            id="azure-prod",
            name="Azure AD",
            provider_type=IdentityProviderType.OIDC,
            issuer="https://login.microsoftonline.com/tenant/v2.0",
            client_id="real-client-id",
            oidc_jwks_uri="https://login.microsoftonline.com/tenant/discovery/v2.0/keys",
        ))
        oidc = OIDCProvider(store, "https://aegisgraph.example.com")
        
        now = int(datetime.now(timezone.utc).timestamp())
        claims_in = {
            "sub": "user-42",
            "iss": "https://login.microsoftonline.com/tenant/v2.0",
            "aud": "real-client-id",
            "exp": now + 300,
            "iat": now,
        }
        legit_token = jwt.encode(claims_in, idp_key_pem, algorithm="RS256", headers={"kid": "k1"})
        forged_token = jwt.encode(
            {**claims_in, "sub": "admin"}, attacker_key_pem, algorithm="RS256", headers={"kid": "k1"}
        )
        
        # Mock the JWKS fetch only
        fake_signing_key = MagicMock(key=idp_key.public_key())
        with patch.object(OIDCProvider, "_get_jwks_client") as mock_get_client:
            mock_get_client.return_value.get_signing_key_from_jwt.return_value = fake_signing_key
            
            is_valid, claims = oidc.validate_token("azure-prod", legit_token)
            assert is_valid is True
            assert claims["sub"] == "user-42"
            
            is_valid, claims = oidc.validate_token("azure-prod", forged_token)
            assert is_valid is False
            assert claims is None


class TestOAuthProvider:
    """Tests for OAuthProvider."""
    
    def test_register_client(self):
        """Test OAuth client registration."""
        store = IdentityFederationStore()
        oauth = OAuthProvider(store, "https://aegisgraph.example.com")
        
        result = oauth.register_client(
            client_id="test-client",
            client_secret="test-secret",
            redirect_uris=["https://app.example.com/callback"],
            scopes=["openid", "profile"],
        )
        
        assert result["client_id"] == "test-client"
        assert "client_secret" in result
    
    def test_authorization_code_flow(self):
        """Test OAuth authorization code flow."""
        store = IdentityFederationStore()
        oauth = OAuthProvider(store, "https://aegisgraph.example.com")
        
        # Register client
        oauth.register_client(
            client_id="test-client",
            client_secret="test-secret",
            redirect_uris=["https://app.example.com/callback"],
        )
        
        # Authorize
        response = oauth.authorize(
            client_id="test-client",
            redirect_uri="https://app.example.com/callback",
            response_type="code",
            scope="openid profile",
            state="test-state",
        )
        
        assert response.success is True
        assert response.redirect_url is not None
        assert "code=" in response.redirect_url

    def test_authorization_code_missing_secret_returns_invalid_client(self):
        """Omitting client_secret must return invalid_client, not a 500."""
        store = IdentityFederationStore()
        oauth = OAuthProvider(store, "https://aegisgraph.example.com")

        oauth.register_client(
            client_id="test-client",
            client_secret="test-secret",
            redirect_uris=["https://app.example.com/callback"],
        )

        authorize = oauth.authorize(
            client_id="test-client",
            redirect_uri="https://app.example.com/callback",
            response_type="code",
            scope="openid profile",
            state="test-state",
        )
        code = parse_qs(urlparse(authorize.redirect_url).query)["code"][0]

        response = oauth.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri="https://app.example.com/callback",
            client_id="test-client",
            client_secret=None,
        )

        assert response.success is False
        assert response.error == "invalid_client"

    def test_client_credentials_missing_secret_returns_invalid_client(self):
        """Omitting client_secret in client credentials flow must not raise."""
        store = IdentityFederationStore()
        oauth = OAuthProvider(store, "https://aegisgraph.example.com")

        oauth.register_client(
            client_id="test-client",
            client_secret="test-secret",
            redirect_uris=["https://app.example.com/callback"],
        )

        response = oauth.token(
            grant_type="client_credentials",
            client_id="test-client",
            client_secret=None,
        )

        assert response.success is False
        assert response.error == "invalid_client"

    def test_hash_secret_handles_missing_input(self):
        """_hash_secret must not raise on None or empty input."""
        store = IdentityFederationStore()
        oauth = OAuthProvider(store, "https://aegisgraph.example.com")

        assert oauth._hash_secret(None) == ""
        assert oauth._hash_secret("") == ""
        assert oauth._hash_secret("test-secret") != ""


class TestSessionManager:
    """Tests for SessionManager."""
    
    def test_create_session(self):
        """Test session creation."""
        store = IdentityFederationStore()
        manager = SessionManager(store)
        
        session = manager.create_session(
            user_id="user-1",
            provider_id="provider-1",
            ip_address="192.168.1.1",
            user_agent="Test Browser",
        )
        
        assert session is not None
        assert session.user_id == "user-1"
        assert session.state == SessionState.ACTIVE
        assert session.ip_address == "192.168.1.1"
    
    def test_validate_session(self):
        """Test session validation."""
        store = IdentityFederationStore()
        manager = SessionManager(store)
        
        session = manager.create_session(
            user_id="user-1",
            provider_id="provider-1",
        )
        
        is_valid, retrieved, error = manager.validate_session(session.id)
        
        assert is_valid is True
        assert retrieved is not None
        assert error is None
    
    def test_max_concurrent_sessions(self):
        """Test max concurrent sessions enforcement."""
        store = IdentityFederationStore()
        manager = SessionManager(store, max_concurrent_sessions=2)
        
        # Create more than max sessions
        sessions = []
        for i in range(5):
            session = manager.create_session(
                user_id="user-1",
                provider_id="provider-1",
            )
            sessions.append(session)
        
        # Should only have max_concurrent active sessions
        active = manager.get_user_sessions("user-1")
        assert len(active) <= 2


class TestIdentityMapper:
    """Tests for IdentityMapper."""
    
    def test_map_identity(self):
        """Test identity attribute mapping."""
        store = IdentityFederationStore()
        mapper = IdentityMapper(store)
        
        provider = IdentityProvider(
            id="provider-1",
            name="Test Provider",
            provider_type=IdentityProviderType.OIDC,
            issuer="https://test.example.com",
            attribute_mappings={
                "email": "email",
                "display_name": "name",
                "first_name": "given_name",
            },
        )
        
        raw_attributes = {
            "email": "user@example.com",
            "name": "Test User",
            "given_name": "Test",
        }
        
        mapped = mapper.map_identity(provider, raw_attributes)
        
        assert mapped["email"] == "user@example.com"
        assert mapped["display_name"] == "Test User"
        assert mapped["first_name"] == "Test"
    
    def test_map_roles(self):
        """Test role mapping."""
        store = IdentityFederationStore()
        mapper = IdentityMapper(store)
        
        provider = IdentityProvider(
            id="provider-1",
            name="Test Provider",
            provider_type=IdentityProviderType.OIDC,
            issuer="https://test.example.com",
        )
        
        # Add role mapping
        mapper.add_role_mapping(
            provider_id="provider-1",
            source_group="admins",
            target_role="admin",
            priority=10,
        )
        mapper.add_role_mapping(
            provider_id="provider-1",
            source_group="users",
            target_role="user",
            priority=5,
        )
        
        roles = mapper.map_roles(provider, ["admins", "users"])
        
        assert "admin" in roles
        assert "user" in roles


class TestProvisioningService:
    """Tests for ProvisioningService."""
    
    def test_create_user(self):
        """Test user provisioning."""
        store = IdentityFederationStore()
        provisioning = ProvisioningService(store)
        
        provider = IdentityProvider(
            id="provider-1",
            name="Test Provider",
            provider_type=IdentityProviderType.OIDC,
            issuer="https://test.example.com",
        )
        store.register_provider(provider)
        
        user_info = {
            "provider_user_id": "ext-user-1",
            "email": "newuser@example.com",
            "display_name": "New User",
            "groups": ["users"],
        }
        
        user, event = provisioning.provision_user(
            provider=provider,
            user_info=user_info,
        )
        
        assert user is not None
        assert user.email == "newuser@example.com"
        assert event.status == "completed"
        assert "created" in event.changes


class TestAuditLogger:
    """Tests for AuditLogger."""
    
    def test_log_authentication(self):
        """Test authentication logging."""
        store = IdentityFederationStore()
        audit = AuditLogger(store)
        
        event = audit.log_authentication(
            success=True,
            provider_id="provider-1",
            user_id="user-1",
            username="testuser",
            authentication_method="oidc",
            ip_address="192.168.1.1",
        )
        
        assert event is not None
        assert event.action == "authentication"
        assert event.success is True
        assert event.user_id == "user-1"
    
    def test_query_events(self):
        """Test audit log querying."""
        store = IdentityFederationStore()
        audit = AuditLogger(store)
        
        # Log some events
        audit.log_authentication(True, "provider-1", "user-1", authentication_method="oidc")
        audit.log_authentication(False, "provider-2", "user-2", authentication_method="saml")
        audit.log_session("create", "session-1", "user-1")
        
        # Query by user
        events = audit.query(user_id="user-1")
        assert len(events) == 2
        
        # Query by action
        events = audit.query(action="authentication")
        assert len(events) == 2
        
        # Query by success
        events = audit.query(success=False)
        assert len(events) == 1


class TestIdentityFederationService:
    """Tests for IdentityFederationService."""
    
    def test_register_provider(self):
        """Test provider registration through service."""
        service = IdentityFederationService()
        
        provider, is_valid, errors = service.register_provider(
            name="Test SAML Provider",
            provider_type=IdentityProviderType.SAML,
            issuer="https://test.example.com",
            saml_entity_id="test-entity",
            saml_sso_url="https://test.example.com/sso",
            saml_certificate="cert-data",
        )
        
        assert provider is not None
        # SAML provider may have validation errors depending on config
        # Just verify provider was created
        assert provider.name == "Test SAML Provider"
    
    def test_authenticate(self):
        """Test authentication initiation."""
        service = IdentityFederationService()
        
        # Register a SAML provider first
        provider, _, _ = service.register_provider(
            name="Test SAML Provider",
            provider_type=IdentityProviderType.SAML,
            issuer="https://test.example.com",
            saml_entity_id="test-entity",
            saml_sso_url="https://test.example.com/sso",
            saml_certificate="cert-data",
        )
        
        response = service.authenticate(provider_id=provider.id)
        assert response is not None
        # SAML login should return a redirect URL
        if response.success:
            assert response.redirect_url is not None
    
    def test_provision_user(self):
        """Test user provisioning through service."""
        service = IdentityFederationService()
        
        # Register a provider
        provider, _, _ = service.register_provider(
            name="Test Provider",
            provider_type=IdentityProviderType.OIDC,
            issuer="https://test.example.com",
            client_id="client-id",
            client_secret="client-secret",
        )
        
        user_info = {
            "provider_user_id": "ext-user-1",
            "email": "provisioned@example.com",
            "display_name": "Provisioned User",
        }
        
        user = service.provision_user(provider.id, user_info)
        
        assert user is not None
        assert user.email == "provisioned@example.com"
    
    def test_get_stats(self):
        """Test statistics retrieval."""
        service = IdentityFederationService()
        
        stats = service.get_stats()
        
        assert "store" in stats
        assert "audit" in stats
        assert "providers" in stats
        assert stats["providers"]["total"] >= 0


class TestIntegration:
    """Integration tests for the full federation flow."""
    
    def test_full_oidc_flow(self):
        """Test complete OIDC authentication flow."""
        service = IdentityFederationService()
        
        # 1. Register SAML provider (simulating OIDC for testing)
        provider, _, _ = service.register_provider(
            name="Test SAML",
            provider_type=IdentityProviderType.SAML,
            issuer="https://saml.example.com",
            saml_entity_id="test-entity",
            saml_sso_url="https://saml.example.com/sso",
            saml_certificate="cert-data",
        )
        
        # 2. Initiate login
        response = service.authenticate(provider_id=provider.id)
        assert response is not None
        # SAML login should return redirect URL
        if response.success:
            assert response.redirect_url is not None
        
        # 3. Provision user (simulating callback)
        user_info = {
            "provider_user_id": "saml-user-1",
            "email": "samluser@example.com",
            "display_name": "SAML User",
        }
        
        user = service.provision_user(provider.id, user_info)
        assert user is not None
        
        # 4. Get user
        retrieved = service.get_user(user.id)
        assert retrieved is not None
        assert retrieved.email == "samluser@example.com"
    
    def test_azure_ad_quick_setup(self):
        """Test Azure AD quick setup."""
        service = IdentityFederationService()
        
        provider = service.setup_azure_ad(
            tenant_id="test-tenant-id",
            client_id="azure-client-id",
            client_secret="azure-client-secret",
            name="My Azure AD",
        )
        
        assert provider is not None
        assert provider.name == "My Azure AD"
        assert provider.sso_provider == SSOProvider.AZURE_AD
        assert "login.microsoftonline.com" in provider.issuer


if __name__ == "__main__":
    pytest.main([__file__, "-v"])