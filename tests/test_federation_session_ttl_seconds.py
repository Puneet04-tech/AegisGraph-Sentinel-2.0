"""Federation SSO session TTL must be interpreted in seconds (Issue #3506).

``session_ttl`` is documented and stored in seconds, but the SAML and OIDC
providers computed ``expires_at`` with ``timedelta(hours=...)``, turning the
default 3600-second (1 hour) TTL into a ~150-day session. These tests pin the
expiry calculation to seconds for both providers.
"""

import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

import pytest

from src.identity_federation.models import (
    FederatedUser,
    IdentityProvider,
    IdentityProviderType,
)
from src.identity_federation.oidc_provider import OIDCProvider
from src.identity_federation.saml_provider import SAMLProvider
from src.identity_federation.store import IdentityFederationStore


@pytest.fixture
def short_ttl_store() -> IdentityFederationStore:
    return IdentityFederationStore(session_ttl=300)


@pytest.fixture
def user() -> FederatedUser:
    return FederatedUser(
        id="user-1",
        provider_id="idp-1",
        provider_user_id="external-1",
        email="user@example.com",
    )


@pytest.fixture
def provider() -> IdentityProvider:
    return IdentityProvider(
        id="idp-1",
        name="Corp IdP",
        provider_type=IdentityProviderType.SAML,
        issuer="https://idp.example.com",
    )


def _assert_expiry_is_ttl_seconds(session, ttl_seconds: int) -> None:
    now = datetime.now(timezone.utc)
    diff = session.expires_at - now
    assert abs(diff - timedelta(seconds=ttl_seconds)) < timedelta(seconds=5)


class TestFederationSessionTtlSeconds:
    def test_store_attr_is_named_for_seconds(self):
        assert IdentityFederationStore()._session_ttl_seconds == 3600

    def test_saml_session_uses_seconds(self, short_ttl_store, user, provider):
        saml = SAMLProvider(store=short_ttl_store, service_provider_id="sp-test")
        assertion = ET.Element("assertion")
        session = saml._create_session(user, provider, assertion)
        _assert_expiry_is_ttl_seconds(session, 300)

    def test_oidc_session_uses_seconds(self, short_ttl_store, user, provider):
        oidc = OIDCProvider(store=short_ttl_store, issuer="https://aegisgraph.example.com")
        session = oidc._create_session(user, provider, "id-token")
        _assert_expiry_is_ttl_seconds(session, 300)

    def test_default_ttl_yields_one_hour(self, user, provider):
        store = IdentityFederationStore()  # default 3600 seconds
        saml = SAMLProvider(store=store, service_provider_id="sp-test")
        session = saml._create_session(user, provider, ET.Element("assertion"))
        _assert_expiry_is_ttl_seconds(session, 3600)
