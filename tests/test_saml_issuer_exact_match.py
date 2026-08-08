"""Tests for SAML issuer exact-match provider lookup."""

import pytest

from src.identity_federation.models import IdentityProvider, IdentityProviderType
from src.identity_federation.saml_provider import SAMLProvider
from src.identity_federation.store import IdentityFederationStore


@pytest.fixture
def saml_provider() -> SAMLProvider:
    store = IdentityFederationStore()
    store.register_provider(
        IdentityProvider(
            id="idp-a",
            name="IdP A",
            provider_type=IdentityProviderType.SAML,
            issuer="https://idp.example.com/realms/a",
            saml_sso_url="https://idp.example.com/sso",
        )
    )
    store.register_provider(
        IdentityProvider(
            id="idp-b",
            name="IdP B",
            provider_type=IdentityProviderType.SAML,
            issuer="https://idp.example.com/realms/ab",
            saml_sso_url="https://idp.example.com/sso-b",
        )
    )
    return SAMLProvider(store=store, service_provider_id="sp-test")


class TestSAMLIssuerExactMatch:
    def test_exact_issuer_match(self, saml_provider: SAMLProvider):
        provider = saml_provider._get_provider_by_issuer("https://idp.example.com/realms/a")
        assert provider is not None
        assert provider.id == "idp-a"

    def test_trailing_slash_normalized(self, saml_provider: SAMLProvider):
        provider = saml_provider._get_provider_by_issuer("https://idp.example.com/realms/a/")
        assert provider is not None
        assert provider.id == "idp-a"

    def test_rejects_substring_issuer(self, saml_provider: SAMLProvider):
        # Previously matched via `issuer in provider.issuer` against idp-b
        provider = saml_provider._get_provider_by_issuer("https://idp.example.com/realms/a")
        assert provider is not None
        assert provider.id == "idp-a"
        assert saml_provider._get_provider_by_issuer("https://idp.example.com/realms") is None
        assert saml_provider._get_provider_by_issuer("realms/a") is None

    def test_rejects_empty_or_none_issuer(self, saml_provider: SAMLProvider):
        assert saml_provider._get_provider_by_issuer("") is None
        assert saml_provider._get_provider_by_issuer("   ") is None
        assert saml_provider._get_provider_by_issuer(None) is None
