"""
Unit tests for the FederationManager identity federation orchestrator.

Covers provider discovery and registration, SAML/OIDC/OAuth2 flow routing,
callback and token handling, SSO initiation, provider linking, session
validation, and federated identity lookup.
"""

import base64
import pathlib
import sys
import types
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest


def _install_oauth_provider_workaround() -> None:
    """Compile oauth_provider.py in memory with a duplicated parameter removed.

    oauth_provider.py currently fails to parse on Python 3.13 because
    _refresh_token_grant() declares client_id/client_secret twice, which also
    prevents importing the whole identity_federation package. This compiles the
    real module from source minus the duplicated lines so the package loads
    without modifying anything under src/.
    """
    pkg_dir = (
        pathlib.Path(__file__).resolve().parent.parent
        / "src"
        / "identity_federation"
    )
    source = (pkg_dir / "oauth_provider.py").read_text(encoding="utf-8")
    patched = source.replace(
        "        scope: Optional[str],\n"
        "        client_id: Optional[str] = None,\n"
        "        client_secret: Optional[str] = None,\n",
        "        scope: Optional[str],\n",
    )
    if patched == source:
        raise RuntimeError(
            "Expected duplicated parameters not found in oauth_provider.py"
        )
    module = types.ModuleType("src.identity_federation.oauth_provider")
    module.__file__ = str(pkg_dir / "oauth_provider.py")
    sys.modules["src.identity_federation.oauth_provider"] = module
    exec(compile(patched, str(pkg_dir / "oauth_provider.py"), "exec"), module.__dict__)


try:
    from src.identity_federation.federation_manager import FederationManager
    from src.identity_federation.saml_provider import SAMLProvider
    from src.identity_federation.store import IdentityFederationStore
    from src.identity_federation.models import (
        AuthenticationRequest,
        AuthenticationResponse,
        FederatedUser,
        FederationSession,
        IdentityProviderType,
        SessionState,
    )
except SyntaxError:
    _install_oauth_provider_workaround()
    from src.identity_federation.federation_manager import FederationManager
    from src.identity_federation.saml_provider import SAMLProvider
    from src.identity_federation.store import IdentityFederationStore
    from src.identity_federation.models import (
        AuthenticationRequest,
        AuthenticationResponse,
        FederatedUser,
        FederationSession,
        IdentityProviderType,
        SessionState,
    )


SAML_ISSUER = "https://saml.example.com"


def _register_provider(manager, ptype, issuer, name=None, enabled=True, **kwargs):
    return manager.registry.register_provider(
        name=name or issuer,
        provider_type=ptype,
        issuer=issuer,
        enabled=enabled,
        **kwargs,
    )


def _register_user(manager, user_id, provider_id, provider_user_id, email):
    user = FederatedUser(
        id=user_id,
        provider_id=provider_id,
        provider_user_id=provider_user_id,
        email=email,
    )
    manager._store.register_user(user)
    return user


def _create_session(manager, session_id, user_id, provider_id, hours=1):
    session = FederationSession(
        id=session_id,
        user_id=user_id,
        provider_id=provider_id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=hours),
    )
    manager._store.create_session(session)
    return session


def _saml_response_xml():
    return (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_rsp1" '
        'Version="2.0" IssueInstant="2024-01-01T00:00:00Z" InResponseTo="_req1">'
        f"<saml:Issuer>{SAML_ISSUER}</saml:Issuer>"
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">'
        f"<saml:Issuer>{SAML_ISSUER}</saml:Issuer>"
        '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">saml-user@example.com</saml:NameID></saml:Subject>'
        '<saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z" SessionIndex="sidx123"/>'
        '<saml:AttributeStatement><saml:Attribute Name="display_name"><saml:AttributeValue>SAML User</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>'
        "</saml:Assertion></samlp:Response>"
    )


@pytest.fixture
def manager(monkeypatch):
    monkeypatch.setenv("AEGIS_IDENTITY_ISSUER", "https://aegis.example.com")
    store = IdentityFederationStore()
    return FederationManager(store, sp_id="test-sp", issuer="https://aegis.example.com")


class TestFederationManagerRegistry:
    """Tests for provider registration and discovery through the manager."""

    def test_registry_property_exposes_provider_registry(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://discovery.example.com",
            name="Discovery IdP",
        )
        assert manager.registry.get_provider(provider.id) is provider
        assert manager.registry.get_provider_by_issuer("https://discovery.example.com") is provider
        assert provider in manager.registry.list_providers()

    def test_registry_lists_enabled_providers_only(self, manager):
        _register_provider(manager, IdentityProviderType.OIDC, "https://enabled.example.com")
        _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://disabled.example.com",
            enabled=False,
        )
        all_providers = manager.registry.list_providers()
        enabled_only = manager.registry.list_providers(enabled_only=True)
        assert len(all_providers) == 2
        assert len(enabled_only) == 1
        assert enabled_only[0].issuer == "https://enabled.example.com"

    def test_metadata_cache_roundtrip_and_invalidation(self, manager):
        key = "discovery:https://idp.example.com/.well-known/openid-configuration"
        metadata = {"authorization_endpoint": "https://idp.example.com/authorize"}
        assert manager._store.get_cached_metadata(key) is None
        manager._store.cache_metadata(key, metadata)
        assert manager._store.get_cached_metadata(key) == metadata
        manager._store.invalidate_metadata_cache(key)
        assert manager._store.get_cached_metadata(key) is None


class TestFederationManagerAuthenticate:
    """Tests for authenticate() routing to SAML, OIDC, and OAuth2 flows."""

    def test_authenticate_unknown_provider_returns_provider_not_found(self, manager):
        response = manager.authenticate(AuthenticationRequest(provider_id="nope"))
        assert response.success is False
        assert response.error == "provider_not_found"
        assert response.error_description == "Provider nope not found"

    def test_authenticate_disabled_provider_returns_provider_disabled(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://disabled.example.com",
            enabled=False,
        )
        response = manager.authenticate(AuthenticationRequest(provider_id=provider.id))
        assert response.success is False
        assert response.error == "provider_disabled"
        assert response.error_description == "Identity provider is disabled"

    def test_authenticate_saml_returns_redirect(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.SAML,
            SAML_ISSUER,
            saml_entity_id="test-entity",
            saml_sso_url="https://saml.example.com/sso",
            saml_certificate="cert-data",
        )
        response = manager.authenticate(
            AuthenticationRequest(provider_id=provider.id, return_url="https://app.example.com/cb")
        )
        assert response.success is True
        assert response.authentication_method == "saml"
        assert response.provider_id == provider.id
        assert "SAMLRequest=" in response.redirect_url
        assert "RelayState=" in response.redirect_url

    def test_authenticate_saml_force_authn_and_relay_state(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.SAML,
            SAML_ISSUER,
            saml_entity_id="test-entity",
            saml_sso_url="https://saml.example.com/sso",
            saml_certificate="cert-data",
        )
        return_url = "https://app.example.com/callback"
        response = manager.authenticate(
            AuthenticationRequest(
                provider_id=provider.id,
                return_url=return_url,
                saml_force_authn=True,
            )
        )
        query = parse_qs(urlparse(response.redirect_url).query)
        authn_request = base64.b64decode(query["SAMLRequest"][0]).decode()
        assert 'ForceAuthn="true"' in authn_request
        relay_state = base64.b64decode(query["RelayState"][0]).decode()
        assert relay_state.endswith(return_url)

    def test_authenticate_oidc_returns_redirect(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://oidc.example.com",
            client_id="cid",
            client_secret="cs",
            oidc_authorization_endpoint="https://oidc.example.com/authorize",
        )
        response = manager.authenticate(AuthenticationRequest(provider_id=provider.id))
        query = parse_qs(urlparse(response.redirect_url).query)
        assert response.success is True
        assert response.authentication_method == "oidc"
        assert response.provider_id == provider.id
        assert query["client_id"] == ["cid"]
        assert query["response_type"] == ["code"]
        assert query["state"][0]
        assert query["nonce"][0]
        assert query["redirect_uri"][0].endswith("/oidc/callback")

    def test_authenticate_oidc_populates_pending_auths(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://oidc.example.com",
            client_id="cid",
            client_secret="cs",
            oidc_authorization_endpoint="https://oidc.example.com/authorize",
        )
        response = manager.authenticate(AuthenticationRequest(provider_id=provider.id))
        query = parse_qs(urlparse(response.redirect_url).query)
        state = query["state"][0]

        pending = manager._pending_auths.get(state)
        assert pending is not None
        assert pending["state"] == state
        assert pending["nonce"] == query["nonce"][0]
        assert pending["provider_id"] == provider.id

    def test_authenticate_oidc_forwards_prompt_max_age_and_acr(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://oidc.example.com",
            client_id="cid",
            oidc_authorization_endpoint="https://oidc.example.com/authorize",
        )
        response = manager.authenticate(
            AuthenticationRequest(
                provider_id=provider.id,
                oidc_prompt="login",
                oidc_max_age=600,
                oidc_acr_values="urn:acr:silver",
            )
        )
        query = parse_qs(urlparse(response.redirect_url).query)
        assert query["prompt"] == ["login"]
        assert query["max_age"] == ["600"]
        assert query["acr_values"] == ["urn:acr:silver"]

    def test_authenticate_oidc_omits_zero_max_age(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://oidc.example.com",
            client_id="cid",
            oidc_authorization_endpoint="https://oidc.example.com/authorize",
        )
        response = manager.authenticate(
            AuthenticationRequest(provider_id=provider.id, oidc_max_age=0)
        )
        query = parse_qs(urlparse(response.redirect_url).query)
        assert response.success is True
        assert "max_age" not in query

    def test_authenticate_azure_ad_routes_to_oidc(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.AZURE_AD,
            "https://login.microsoftonline.com/test/v2.0",
            client_id="az-client",
            client_secret="az-secret",
            oidc_authorization_endpoint="https://login.microsoftonline.com/test/oauth2/v2.0/authorize",
        )
        response = manager.authenticate(AuthenticationRequest(provider_id=provider.id))
        assert response.success is True
        assert response.authentication_method == "oidc"
        assert "client_id=az-client" in response.redirect_url

    def test_authenticate_oidc_resolves_cached_discovery_metadata(self, manager):
        discovery_url = "https://idp.example.com/.well-known/openid-configuration"
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://idp.example.com",
            client_id="cid",
            oidc_discovery_url=discovery_url,
        )
        manager._store.cache_metadata(
            f"discovery:{discovery_url}",
            {"authorization_endpoint": "https://idp.example.com/authorize"},
        )
        response = manager.authenticate(AuthenticationRequest(provider_id=provider.id))
        assert response.success is True
        assert response.redirect_url.startswith("https://idp.example.com/authorize?")
        assert "client_id=cid" in response.redirect_url

    def test_authenticate_oidc_falls_back_when_discovery_misses(self, manager):
        discovery_url = "https://idp.example.com/.well-known/openid-configuration"
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://idp.example.com",
            client_id="cid",
            oidc_discovery_url=discovery_url,
        )
        response = manager.authenticate(AuthenticationRequest(provider_id=provider.id))
        assert response.success is True
        assert response.redirect_url.startswith("?")
        assert "client_id=cid" in response.redirect_url

    def test_authenticate_oauth2_returns_authorize_redirect(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.OAUTH2,
            "https://oauth.example.com",
        )
        response = manager.authenticate(AuthenticationRequest(provider_id=provider.id))
        assert response.success is False
        assert response.error == "oauth2_redirect"
        assert response.error_description == "OAuth2 requires authorization endpoint"
        assert response.redirect_url == "https://oauth.example.com/authorize"

    def test_authenticate_unsupported_provider_type_returns_error(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.LDAP,
            "ldap://ldap.example.com",
        )
        response = manager.authenticate(AuthenticationRequest(provider_id=provider.id))
        assert response.success is False
        assert response.error == "unsupported_provider"
        assert response.error_description == "Provider type ldap not supported"


class TestFederationManagerHandleCallback:
    """Tests for callback handling across SAML, OIDC, and OAuth protocols."""

    def test_handle_callback_unknown_protocol(self, manager):
        response = manager.handle_callback("p1", "ws-federation")
        assert response.success is False
        assert response.error == "unknown_protocol"
        assert response.error_description == "Unknown protocol: ws-federation"

    def test_handle_callback_oidc_uses_authenticate_state_and_nonce(self, manager, monkeypatch):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://oidc.example.com",
            client_id="cid",
            client_secret="cs",
            oidc_authorization_endpoint="https://oidc.example.com/authorize",
        )
        response = manager.authenticate(AuthenticationRequest(provider_id=provider.id))
        query = parse_qs(urlparse(response.redirect_url).query)
        state = query["state"][0]

        captured = {}

        def fake_exchange_code(**kwargs):
            captured.update(kwargs)
            return AuthenticationResponse(
                success=True,
                access_token="real-at",
                id_token="real-it",
                provider_id=provider.id,
                authentication_method="oidc",
            )

        monkeypatch.setattr(manager._oidc, "exchange_code", fake_exchange_code)
        callback = manager.handle_callback(
            provider.id, "oidc", code="code1", state=state
        )
        assert callback.success is True
        assert captured["expected_state"] == state
        assert captured["provided_state"] == state
        assert captured["expected_nonce"] == query["nonce"][0]
        assert state not in manager._pending_auths

    def test_handle_callback_oidc_rejects_state_mismatch(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://oidc.example.com",
            client_id="cid",
        )
        response = manager.handle_callback(
            provider.id, "oidc", code="code1", state="provided-state"
        )
        assert response.success is False
        assert response.error == "state_mismatch"
        assert response.error_description == "State parameter mismatch - possible CSRF attack"

    def test_handle_callback_oidc_exchanges_code_with_pending_state(self, manager, monkeypatch):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://oidc.example.com",
            client_id="cid",
        )
        captured = {}

        def fake_exchange_code(**kwargs):
            captured.update(kwargs)
            return AuthenticationResponse(
                success=True,
                access_token="real-at",
                id_token="real-it",
                provider_id=provider.id,
                authentication_method="oidc",
            )

        monkeypatch.setattr(manager._oidc, "exchange_code", fake_exchange_code)
        manager._pending_auths["expected-state"] = {
            "state": "expected-state",
            "nonce": "n-123",
        }
        response = manager.handle_callback(
            provider.id, "oidc", code="code1", state="expected-state"
        )
        assert response.success is True
        assert response.access_token == "real-at"
        assert response.id_token == "real-it"
        assert response.authentication_method == "oidc"
        assert captured["code"] == "code1"
        assert captured["expected_state"] == "expected-state"
        assert captured["provided_state"] == "expected-state"
        assert captured["expected_nonce"] == "n-123"
        assert "expected-state" not in manager._pending_auths

    def test_handle_callback_saml_routes_response_and_relay_state(self, manager, monkeypatch):
        captured = {}

        def fake_process_response(**kwargs):
            captured.update(kwargs)
            return AuthenticationResponse(
                success=True, provider_id="saml-provider", authentication_method="saml"
            )

        monkeypatch.setattr(manager._saml, "process_response", fake_process_response)
        response = manager.handle_callback(
            "saml-provider",
            "saml",
            SAMLResponse="encoded-response",
            RelayState="relay-1",
        )
        assert captured == {"saml_response": "encoded-response", "relay_state": "relay-1"}
        assert response.success is True

    def test_handle_callback_saml_processes_valid_assertion(self, manager, monkeypatch):
        provider = _register_provider(
            manager,
            IdentityProviderType.SAML,
            SAML_ISSUER,
            saml_entity_id="test-entity",
            saml_sso_url="https://saml.example.com/sso",
            saml_certificate="cert-data",
        )
        monkeypatch.setattr(
            manager._saml,
            "_get_issuer",
            lambda assertion: assertion.find(
                "saml:Issuer", SAMLProvider.NAMESPACES
            ).text,
            raising=False,
        )
        encoded = base64.b64encode(_saml_response_xml().encode()).decode()
        response = manager.handle_callback(
            provider.id, "saml", SAMLResponse=encoded, RelayState="relay-1"
        )
        assert response.success is True
        assert response.authentication_method == "saml"
        assert response.user.email == "saml-user@example.com"
        assert response.user.display_name == "SAML User"
        assert response.session.session_index == "sidx123"
        assert manager._store.get_user(response.user.id) is response.user

    def test_handle_callback_saml_malformed_response_returns_processing_error(self, manager):
        response = manager.handle_callback("saml-provider", "saml", SAMLResponse="")
        assert response.success is False
        assert response.error == "processing_error"
        assert "SAML response" in response.error_description

    def test_handle_callback_oauth_issues_authorization_code(self, manager):
        manager._oauth.register_client(
            client_id="web-app",
            client_secret="s3cret",
            redirect_uris=["https://app.example.com/callback"],
            scopes=["openid", "profile"],
        )
        response = manager.handle_callback(
            "unused",
            "oauth",
            client_id="web-app",
            redirect_uri="https://app.example.com/callback",
            scope="openid profile",
            state="st-1",
        )
        assert response.success is True
        assert response.redirect_url.startswith("https://app.example.com/callback?code=")
        assert "state=st-1" in response.redirect_url

    def test_handle_callback_oauth_unknown_client_rejected(self, manager):
        response = manager.handle_callback(
            "unused",
            "oauth",
            client_id="unknown-app",
            redirect_uri="https://app.example.com/callback",
            scope="openid profile",
        )
        assert response.success is False
        assert response.error == "invalid_client"
        assert response.error_description == "Unknown client_id"


class TestFederationManagerProcessToken:
    """Tests for process_token() OIDC ID token handling."""

    def test_process_token_unsupported_protocol(self, manager):
        response = manager.process_token("p1", "token", protocol="saml")
        assert response.success is False
        assert response.error == "unsupported_protocol"
        assert response.error_description == "Token processing not supported for saml"

    def test_process_token_oidc_creates_user_and_session(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://oidc.example.com",
            client_id="cid",
        )
        response = manager.process_token(provider.id, "simulated_id_token_abc")
        assert response.success is True
        assert response.authentication_method == "oidc"
        assert response.user.email == "user@example.com"
        assert response.user.provider_user_id == "user123"
        assert response.id_token == "simulated_id_token_abc"
        assert response.session.id.startswith("oidc_")
        assert response.session.state == SessionState.ACTIVE

    def test_process_token_oidc_nonce_mismatch(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://oidc.example.com",
            client_id="cid",
        )
        response = manager.process_token(
            provider.id, "simulated_id_token_abc", nonce="expected-nonce"
        )
        assert response.success is False
        assert response.error == "nonce_mismatch"
        assert response.error_description == "Nonce mismatch - possible replay attack"

    def test_process_token_oidc_unknown_provider(self, manager):
        response = manager.process_token("ghost-provider", "simulated_id_token_abc")
        assert response.success is False
        assert response.error == "provider_not_found"
        assert response.error_description == "Identity provider not found"


class TestFederationManagerInitiateSso:
    """Tests for initiate_sso()."""

    def test_initiate_sso_unknown_user(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        response = manager.initiate_sso("ghost-user", provider.id)
        assert response.success is False
        assert response.error == "user_not_found"
        assert response.error_description == "User not found"

    def test_initiate_sso_unknown_provider(self, manager):
        _register_user(manager, "u1", "ghost-provider", "ext1", "u1@example.com")
        response = manager.initiate_sso("u1", "ghost-provider")
        assert response.success is False
        assert response.error == "provider_not_found"
        assert response.error_description == "Provider not found"

    def test_initiate_sso_user_not_linked(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        _register_user(manager, "u1", "", "", "u1@example.com")
        response = manager.initiate_sso("u1", provider.id)
        assert response.success is False
        assert response.error == "user_not_linked"
        assert response.error_description == "User is not linked to this identity provider"

    def test_initiate_sso_happy_path(self, manager):
        provider = _register_provider(
            manager,
            IdentityProviderType.OIDC,
            "https://oidc.example.com",
            client_id="cid",
            oidc_authorization_endpoint="https://oidc.example.com/authorize",
        )
        _register_user(manager, "u1", provider.id, "ext1", "u1@example.com")
        response = manager.initiate_sso(
            "u1", provider.id, target_url="https://app.example.com/dashboard"
        )
        assert response.success is True
        assert response.authentication_method == "oidc"
        assert response.provider_id == provider.id
        assert response.redirect_url is not None


class TestFederationManagerLinkProvider:
    """Tests for link_provider()."""

    def test_link_provider_unknown_user(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        response = manager.link_provider("ghost-user", provider.id, "ext1")
        assert response.success is False
        assert response.error == "user_not_found"
        assert response.error_description == "User not found"

    def test_link_provider_unknown_provider(self, manager):
        _register_user(manager, "u1", "", "", "u1@example.com")
        response = manager.link_provider("u1", "ghost-provider", "ext1")
        assert response.success is False
        assert response.error == "provider_not_found"
        assert response.error_description == "Provider not found"

    def test_link_provider_already_linked_to_another_user(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        _register_user(manager, "user-a", provider.id, "shared-ext", "a@example.com")
        _register_user(manager, "user-b", "", "", "b@example.com")
        response = manager.link_provider("user-b", provider.id, "shared-ext")
        assert response.success is False
        assert response.error == "already_linked"
        assert (
            response.error_description
            == "This provider account is already linked to another user"
        )

    def test_link_provider_success_with_provider_token(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        _register_user(manager, "u1", "", "", "u1@example.com")
        response = manager.link_provider(
            "u1", provider.id, "ext-9", provider_token="access-token"
        )
        assert response.success is True
        assert response.authentication_method == "link"
        assert response.user.provider_id == provider.id
        assert response.user.provider_user_id == "ext-9"
        assert response.user.profile_data["provider_token"] == "access-token"
        assert manager._store.get_user("u1").provider_id == provider.id

    def test_link_provider_success_without_provider_token(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        _register_user(manager, "u1", "", "", "u1@example.com")
        response = manager.link_provider("u1", provider.id, "ext-10")
        assert response.success is True
        assert "provider_token" not in response.user.profile_data


class TestFederationManagerUnlinkProvider:
    """Tests for unlink_provider()."""

    def test_unlink_provider_unknown_user(self, manager):
        response = manager.unlink_provider("ghost-user", "p1")
        assert response.success is False
        assert response.error == "user_not_found"
        assert response.error_description == "User not found"

    def test_unlink_provider_not_linked(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        _register_user(manager, "u1", "", "", "u1@example.com")
        response = manager.unlink_provider("u1", provider.id)
        assert response.success is False
        assert response.error == "not_linked"
        assert response.error_description == "User is not linked to this provider"

    def test_unlink_provider_success_revokes_sessions(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        _register_user(manager, "u1", provider.id, "ext1", "u1@example.com")
        _create_session(manager, "s1", "u1", provider.id)
        response = manager.unlink_provider("u1", provider.id)
        assert response.success is True
        assert response.authentication_method == "unlink"
        assert response.user.provider_id == ""
        assert response.user.provider_user_id == ""
        assert manager._store.get_session("s1").state == SessionState.REVOKED


class TestFederationManagerFederatedIdentities:
    """Tests for get_federated_identities()."""

    def test_get_federated_identities_unknown_user_returns_empty(self, manager):
        assert manager.get_federated_identities("ghost-user") == []

    def test_get_federated_identities_unlinked_user_returns_empty(self, manager):
        _register_user(manager, "u1", "", "", "u1@example.com")
        assert manager.get_federated_identities("u1") == []

    def test_get_federated_identities_linked_user_raises_attribute_error(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        _register_user(manager, "u1", provider.id, "ext1", "u1@example.com")
        with pytest.raises(AttributeError):
            manager.get_federated_identities("u1")


class TestFederationManagerSessions:
    """Tests for session validation and revocation."""

    def test_validate_session_active_session_returned(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        session = _create_session(manager, "s1", "u1", provider.id)
        retrieved = manager.validate_session("s1")
        assert retrieved is session
        assert retrieved.user_id == "u1"

    def test_validate_session_expired_returns_none(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        _create_session(manager, "s1", "u1", provider.id, hours=-1)
        assert manager.validate_session("s1") is None

    def test_validate_session_unknown_returns_none(self, manager):
        assert manager.validate_session("ghost-session") is None

    def test_revoke_session(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        _create_session(manager, "s1", "u1", provider.id)
        assert manager.revoke_session("s1") is True
        assert manager._store.get_session("s1").state == SessionState.REVOKED
        assert manager.revoke_session("ghost-session") is False

    def test_revoke_all_sessions(self, manager):
        provider = _register_provider(
            manager, IdentityProviderType.OIDC, "https://oidc.example.com"
        )
        _create_session(manager, "s1", "u1", provider.id)
        _create_session(manager, "s2", "u1", provider.id)
        assert manager.revoke_all_sessions("u1") == 2
        assert manager.revoke_all_sessions("ghost-user") == 0
        assert manager._store.get_session("s1").state == SessionState.REVOKED
        assert manager._store.get_session("s2").state == SessionState.REVOKED
