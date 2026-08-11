"""OAuth2 authorization codes must be strictly single-use (Issue #3513).

The code's used-flag was checked and set in separate steps, so two threads
exchanging the same code concurrently could both pass the check and receive
tokens. These tests pin atomic redemption under concurrency and sequential
replay rejection.
"""

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlparse

from src.identity_federation.oauth_provider import OAuthProvider
from src.identity_federation.store import IdentityFederationStore


def _issuer_code(oauth: OAuthProvider) -> str:
    response = oauth.authorize(
        client_id="client-1",
        redirect_uri="https://app.example.com/callback",
        response_type="code",
        scope="openid",
    )
    assert response.success is True
    return parse_qs(urlparse(response.redirect_url).query)["code"][0]


class TestAuthCodeSingleUse:
    def test_replay_after_success_is_rejected(self):
        oauth = OAuthProvider(IdentityFederationStore(), "https://aegisgraph.example.com")
        oauth.register_client(
            client_id="client-1",
            client_secret="secret-1",
            redirect_uris=["https://app.example.com/callback"],
        )
        code = _issuer_code(oauth)

        first = oauth.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri="https://app.example.com/callback",
            client_id="client-1",
            client_secret="secret-1",
        )
        second = oauth.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri="https://app.example.com/callback",
            client_id="client-1",
            client_secret="secret-1",
        )

        assert first.success is True
        assert second.success is False
        assert second.error == "invalid_grant"

    def test_concurrent_exchange_redeems_exactly_once(self):
        oauth = OAuthProvider(IdentityFederationStore(), "https://aegisgraph.example.com")
        oauth.register_client(
            client_id="client-1",
            client_secret="secret-1",
            redirect_uris=["https://app.example.com/callback"],
        )
        code = _issuer_code(oauth)

        def exchange(_):
            return oauth.token(
                grant_type="authorization_code",
                code=code,
                redirect_uri="https://app.example.com/callback",
                client_id="client-1",
                client_secret="secret-1",
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            responses = list(pool.map(exchange, range(64)))

        succeeded = [r for r in responses if r.success]
        assert len(succeeded) == 1
        assert len(succeeded[0].access_token) > 0
