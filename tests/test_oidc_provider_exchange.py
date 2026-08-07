"""OIDC authorization-code exchange, discovery, introspection and userinfo.

`exchange_code` used to return `f"simulated_access_token_{code}"` with
`success=True` without contacting the provider at all, so any caller reaching
the callback with a matching `state` received a successful authentication.
Discovery returned `{}`, introspection self-attested, and userinfo never called
the provider. These tests drive the real flow against a mocked transport.
"""

from __future__ import annotations

import pytest

from src.identity_federation import oidc_provider as oidc_module
from src.identity_federation.models import IdentityProvider, IdentityProviderType
from src.identity_federation.oidc_provider import OIDCProvider
from src.identity_federation.store import IdentityFederationStore

ISSUER = "https://sentinel.example"
PROVIDER_ID = "idp_main"


class FakeResponse:
    def __init__(self, status_code=200, payload=None, invalid_json=False):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self._invalid_json = invalid_json

    def json(self):
        if self._invalid_json:
            raise ValueError("not json")
        return self._payload


class FakeTransport:
    """Stands in for `requests`, recording calls and replaying scripted results."""

    def __init__(self):
        self.post_calls = []
        self.get_calls = []
        self.post_results = []
        self.get_results = []

    def post(self, url, data=None, auth=None, timeout=None, verify=None, headers=None):
        self.post_calls.append(
            {"url": url, "data": data, "auth": auth, "timeout": timeout, "verify": verify}
        )
        if not self.post_results:
            return FakeResponse(200, {})
        result = self.post_results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def get(self, url, timeout=None, verify=None, headers=None):
        self.get_calls.append(
            {"url": url, "timeout": timeout, "verify": verify, "headers": headers or {}}
        )
        if not self.get_results:
            return FakeResponse(200, {})
        result = self.get_results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture
def transport(monkeypatch):
    fake = FakeTransport()
    monkeypatch.setattr(oidc_module, "requests", fake)
    return fake


@pytest.fixture
def store():
    return IdentityFederationStore()


@pytest.fixture
def provider(store):
    record = IdentityProvider(
        id=PROVIDER_ID,
        name="Corp IdP",
        provider_type=IdentityProviderType.OIDC,
        issuer="https://idp.example",
        client_id="client-abc",
        client_secret="secret-xyz",
        oidc_token_endpoint="https://idp.example/token",
        oidc_userinfo_endpoint="https://idp.example/userinfo",
        oidc_jwks_uri="https://idp.example/jwks",
        oidc_discovery_url="https://idp.example/.well-known/openid-configuration",
    )
    store.register_provider(record)
    return record


@pytest.fixture
def oidc(store, provider):
    engine = OIDCProvider(store=store, issuer=ISSUER)
    # No sleeping between retries in tests.
    engine._retry_backoff = 0
    return engine


def _valid_claims(nonce=None):
    claims = {"sub": "user-1", "email": "user@example.com", "iss": "https://idp.example"}
    if nonce is not None:
        claims["nonce"] = nonce
    return claims


@pytest.fixture
def accept_id_token(monkeypatch):
    """Make validate_token succeed, isolating exchange from JWKS verification."""

    def _install(claims):
        monkeypatch.setattr(
            OIDCProvider, "validate_token", lambda self, pid, token, hint=None: (True, claims)
        )

    return _install


@pytest.fixture
def reject_id_token(monkeypatch):
    monkeypatch.setattr(
        OIDCProvider, "validate_token", lambda self, pid, token, hint=None: (False, None)
    )


class TestNoSimulatedTokensRemain:
    def test_a_failed_exchange_never_returns_a_token(self, oidc, transport):
        transport.post_results = [FakeResponse(400, {"error": "invalid_grant"})]

        response = oidc.exchange_code(PROVIDER_ID, "code-1", "st", "st")

        assert response.success is False
        assert response.access_token is None
        assert response.id_token is None

    def test_no_response_ever_contains_a_simulated_token_string(
        self, oidc, transport, accept_id_token
    ):
        accept_id_token(_valid_claims())
        transport.post_results = [
            FakeResponse(200, {"access_token": "real-at", "id_token": "real-it"})
        ]

        response = oidc.exchange_code(PROVIDER_ID, "code-1", "st", "st")

        assert response.success is True
        assert "simulated" not in (response.access_token or "")
        assert "simulated" not in (response.id_token or "")
        assert response.access_token == "real-at"

    def test_the_provider_is_actually_contacted(self, oidc, transport, accept_id_token):
        accept_id_token(_valid_claims())
        transport.post_results = [FakeResponse(200, {"id_token": "real-it"})]

        oidc.exchange_code(PROVIDER_ID, "code-1", "st", "st")

        assert len(transport.post_calls) == 1
        assert transport.post_calls[0]["url"] == "https://idp.example/token"


class TestExchangeRequestShape:
    def test_sends_the_authorization_code_grant(self, oidc, transport, accept_id_token):
        accept_id_token(_valid_claims())
        transport.post_results = [FakeResponse(200, {"id_token": "it"})]

        oidc.exchange_code(PROVIDER_ID, "the-code", "st", "st")

        data = transport.post_calls[0]["data"]
        assert data["grant_type"] == "authorization_code"
        assert data["code"] == "the-code"
        assert data["client_id"] == "client-abc"

    def test_authenticates_with_client_credentials(self, oidc, transport, accept_id_token):
        accept_id_token(_valid_claims())
        transport.post_results = [FakeResponse(200, {"id_token": "it"})]

        oidc.exchange_code(PROVIDER_ID, "code", "st", "st")

        assert transport.post_calls[0]["auth"] == ("client-abc", "secret-xyz")

    def test_tls_verification_is_enforced_and_a_timeout_is_set(
        self, oidc, transport, accept_id_token
    ):
        accept_id_token(_valid_claims())
        transport.post_results = [FakeResponse(200, {"id_token": "it"})]

        oidc.exchange_code(PROVIDER_ID, "code", "st", "st")

        assert transport.post_calls[0]["verify"] is True
        assert transport.post_calls[0]["timeout"] is not None


class TestExchangeFailureModes:
    def test_state_mismatch_is_rejected_before_any_network_call(self, oidc, transport):
        response = oidc.exchange_code(PROVIDER_ID, "code", "expected", "provided")

        assert response.success is False
        assert response.error == "state_mismatch"
        assert transport.post_calls == []

    def test_unknown_provider_is_rejected(self, oidc, transport):
        response = oidc.exchange_code("nope", "code", "st", "st")
        assert response.success is False
        assert response.error == "provider_not_found"

    def test_token_endpoint_400_fails_the_exchange(self, oidc, transport):
        transport.post_results = [FakeResponse(400, {"error": "invalid_grant"})]
        response = oidc.exchange_code(PROVIDER_ID, "code", "st", "st")

        assert response.success is False
        assert response.error == "token_exchange_failed"
        # A 4xx is not retried: the request itself is wrong.
        assert len(transport.post_calls) == 1

    def test_token_endpoint_500_is_retried_then_fails(self, oidc, transport):
        transport.post_results = [
            FakeResponse(500),
            FakeResponse(500),
            FakeResponse(500),
        ]
        response = oidc.exchange_code(PROVIDER_ID, "code", "st", "st")

        assert response.success is False
        assert len(transport.post_calls) == 3

    def test_a_transient_500_followed_by_success_recovers(
        self, oidc, transport, accept_id_token
    ):
        accept_id_token(_valid_claims())
        transport.post_results = [
            FakeResponse(500),
            FakeResponse(200, {"id_token": "it", "access_token": "at"}),
        ]

        response = oidc.exchange_code(PROVIDER_ID, "code", "st", "st")
        assert response.success is True

    def test_a_timeout_fails_the_exchange(self, oidc, transport):
        transport.post_results = [TimeoutError("timed out")] * 3
        response = oidc.exchange_code(PROVIDER_ID, "code", "st", "st")

        assert response.success is False
        assert response.error == "token_exchange_failed"

    def test_a_non_json_body_fails_the_exchange(self, oidc, transport):
        transport.post_results = [FakeResponse(200, invalid_json=True)]
        response = oidc.exchange_code(PROVIDER_ID, "code", "st", "st")
        assert response.success is False

    def test_missing_id_token_fails_the_exchange(self, oidc, transport):
        transport.post_results = [FakeResponse(200, {"access_token": "at"})]
        response = oidc.exchange_code(PROVIDER_ID, "code", "st", "st")

        assert response.success is False
        assert response.error == "id_token_missing"

    def test_an_invalid_id_token_fails_the_exchange(
        self, oidc, transport, reject_id_token
    ):
        transport.post_results = [FakeResponse(200, {"id_token": "forged"})]
        response = oidc.exchange_code(PROVIDER_ID, "code", "st", "st")

        assert response.success is False
        assert response.error == "id_token_invalid"

    def test_nonce_mismatch_fails_the_exchange(self, oidc, transport, accept_id_token):
        accept_id_token(_valid_claims(nonce="server-nonce"))
        transport.post_results = [FakeResponse(200, {"id_token": "it"})]

        response = oidc.exchange_code(
            PROVIDER_ID, "code", "st", "st", expected_nonce="different"
        )

        assert response.success is False
        assert response.error == "nonce_mismatch"

    def test_matching_nonce_is_accepted(self, oidc, transport, accept_id_token):
        accept_id_token(_valid_claims(nonce="server-nonce"))
        transport.post_results = [FakeResponse(200, {"id_token": "it"})]

        response = oidc.exchange_code(
            PROVIDER_ID, "code", "st", "st", expected_nonce="server-nonce"
        )

        assert response.success is True

    def test_no_token_endpoint_available_fails_cleanly(self, oidc, store, transport):
        record = store.get_provider(PROVIDER_ID)
        record.oidc_token_endpoint = None
        record.oidc_discovery_url = None

        response = oidc.exchange_code(PROVIDER_ID, "code", "st", "st")
        assert response.success is False
        assert response.error == "token_endpoint_unavailable"


class TestDiscovery:
    def test_document_is_fetched(self, oidc, transport):
        transport.get_results = [
            FakeResponse(200, {"issuer": "https://idp.example", "token_endpoint": "https://idp.example/t"})
        ]
        document = oidc._fetch_discovery_document("https://idp.example/.well-known/openid-configuration", expected_issuer="https://idp.example")

        assert document["token_endpoint"] == "https://idp.example/t"
        assert len(transport.get_calls) == 1

    def test_document_is_cached(self, oidc, transport):
        transport.get_results = [FakeResponse(200, {"token_endpoint": "https://idp.example/t"})]
        url = "https://idp.example/.well-known/openid-configuration"

        oidc._fetch_discovery_document(url)
        oidc._fetch_discovery_document(url)

        assert len(transport.get_calls) == 1, "second call should hit the cache"

    def test_issuer_mismatch_is_rejected(self, oidc, transport):
        """A substituted provider must not get to name the token endpoint."""
        transport.get_results = [
            FakeResponse(200, {"issuer": "https://attacker.example", "token_endpoint": "https://attacker.example/t"})
        ]
        document = oidc._fetch_discovery_document("https://idp.example/.well-known/openid-configuration", expected_issuer="https://idp.example")
        assert document == {}

    def test_unreachable_discovery_returns_empty(self, oidc, transport):
        transport.get_results = [ConnectionError("down")] * 3
        assert oidc._fetch_discovery_document("https://idp.example/.well-known/x") == {}

    def test_404_discovery_returns_empty(self, oidc, transport):
        transport.get_results = [FakeResponse(404)]
        assert oidc._fetch_discovery_document("https://idp.example/.well-known/x") == {}

    def test_token_endpoint_is_discovered_when_unconfigured(
        self, oidc, store, transport, accept_id_token
    ):
        accept_id_token(_valid_claims())
        store.get_provider(PROVIDER_ID).oidc_token_endpoint = None
        transport.get_results = [
            FakeResponse(200, {"issuer": "https://idp.example", "token_endpoint": "https://idp.example/discovered"})
        ]
        transport.post_results = [FakeResponse(200, {"id_token": "it"})]

        response = oidc.exchange_code(PROVIDER_ID, "code", "st", "st")

        assert response.success is True
        assert transport.post_calls[0]["url"] == "https://idp.example/discovered"


class TestIntrospection:
    def test_provider_endpoint_is_called_when_advertised(self, oidc, transport):
        transport.get_results = [
            FakeResponse(200, {"issuer": "https://idp.example", "introspection_endpoint": "https://idp.example/introspect"})
        ]
        transport.post_results = [FakeResponse(200, {"active": False})]

        result = oidc.introspect_token(PROVIDER_ID, "some-token")

        assert result == {"active": False}
        assert transport.post_calls[0]["url"] == "https://idp.example/introspect"

    def test_a_revoked_token_is_reported_inactive(self, oidc, transport, accept_id_token):
        """Local validation would say 'active'; the provider says otherwise."""
        accept_id_token(_valid_claims())
        transport.get_results = [
            FakeResponse(200, {"issuer": "https://idp.example", "introspection_endpoint": "https://idp.example/introspect"})
        ]
        transport.post_results = [FakeResponse(200, {"active": False})]

        assert oidc.introspect_token(PROVIDER_ID, "revoked")["active"] is False

    def test_unreachable_provider_reports_inactive_not_active(
        self, oidc, transport, accept_id_token
    ):
        accept_id_token(_valid_claims())
        transport.get_results = [
            FakeResponse(200, {"issuer": "https://idp.example", "introspection_endpoint": "https://idp.example/introspect"})
        ]
        transport.post_results = [ConnectionError("down")] * 3

        result = oidc.introspect_token(PROVIDER_ID, "token")
        assert result["active"] is False
        assert result["error"] == "introspection_unavailable"

    def test_local_fallback_is_labelled(self, oidc, transport, accept_id_token):
        accept_id_token(_valid_claims())
        transport.get_results = [FakeResponse(200, {"issuer": "https://idp.example"})]

        result = oidc.introspect_token(PROVIDER_ID, "token")
        assert result["active"] is True
        assert result["introspection_source"] == "local_validation"

    def test_unknown_provider_is_inactive(self, oidc, transport):
        assert oidc.introspect_token("nope", "token") == {"active": False}


class TestUserInfo:
    def test_the_userinfo_endpoint_is_called(self, oidc, transport):
        transport.get_results = [FakeResponse(200, {"sub": "u1", "email": "a@b.c"})]

        info = oidc.get_userinfo(PROVIDER_ID, "access-token")

        assert info is not None
        assert transport.get_calls[0]["url"] == "https://idp.example/userinfo"

    def test_the_access_token_is_sent_as_a_bearer_credential(self, oidc, transport):
        transport.get_results = [FakeResponse(200, {"sub": "u1"})]

        oidc.get_userinfo(PROVIDER_ID, "access-token")

        assert transport.get_calls[0]["headers"]["Authorization"] == "Bearer access-token"

    def test_a_failed_userinfo_call_returns_none(self, oidc, transport):
        transport.get_results = [FakeResponse(401)]
        assert oidc.get_userinfo(PROVIDER_ID, "bad-token") is None

    def test_unknown_provider_returns_none(self, oidc, transport):
        assert oidc.get_userinfo("nope", "token") is None
