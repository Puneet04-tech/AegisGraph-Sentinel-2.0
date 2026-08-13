"""OAuth2 authorization codes must be bound to the requesting client (Issue #3507).

RFC 6749 §4.1.3 requires the token endpoint to reject a code exchange where the
requesting client is not the client that originally obtained the authorization
code. These tests pin that binding check.
"""

from urllib.parse import parse_qs, urlparse

from src.identity_federation.oauth_provider import OAuthProvider
from src.identity_federation.store import IdentityFederationStore

REDIRECT_URI = "https://app.example.com/cb"


def _oauth_with_two_clients() -> OAuthProvider:
    store = IdentityFederationStore()
    oauth = OAuthProvider(store, "https://aegisgraph.example.com")
    oauth.register_client(
        "client-a", "secret-a", [REDIRECT_URI], ["openid", "profile"]
    )
    oauth.register_client(
        "client-b", "secret-b", [REDIRECT_URI], ["openid", "profile"]
    )
    return oauth


def _issue_code(oauth: OAuthProvider) -> str:
    authorize = oauth.authorize(
        client_id="client-a",
        redirect_uri=REDIRECT_URI,
        response_type="code",
        scope="openid",
    )
    assert authorize.success is True
    return parse_qs(urlparse(authorize.redirect_url).query)["code"][0]


class TestAuthorizationCodeClientBinding:
    def test_code_issued_to_client_a_rejected_when_redeemed_by_client_b(self):
        oauth = _oauth_with_two_clients()
        code = _issue_code(oauth)

        response = oauth.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT_URI,
            client_id="client-b",
            client_secret="secret-b",
        )

        assert response.success is False
        assert response.error == "invalid_grant"
        assert "different client" in (response.error_description or "")

    def test_code_redeemed_by_issuing_client_succeeds(self):
        oauth = _oauth_with_two_clients()
        code = _issue_code(oauth)

        response = oauth.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT_URI,
            client_id="client-a",
            client_secret="secret-a",
        )

        assert response.success is True
        assert response.access_token is not None

    def test_rejected_cross_client_code_is_not_consumed(self):
        oauth = _oauth_with_two_clients()
        code = _issue_code(oauth)

        oauth.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT_URI,
            client_id="client-b",
            client_secret="secret-b",
        )

        # The code remains redeemable by its legitimate owner.
        response = oauth.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT_URI,
            client_id="client-a",
            client_secret="secret-a",
        )
        assert response.success is True
