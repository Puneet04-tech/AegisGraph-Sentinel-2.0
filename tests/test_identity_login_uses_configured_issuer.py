"""The federated login routes must use the deployment's configured issuer.

The issuer is the host an identity provider sends the user back to, and for
SAML it is where the signed assertion is posted. #2438 made it configurable
through AEGIS_IDENTITY_ISSUER, but the OIDC login handler built its own
provider with the placeholder domain written in at the call site, which
overrode the configuration for the one flow that uses it.
"""

import io
import re

import pytest

from src.identity_federation import IdentityFederationService
from src.identity_federation.issuer import ISSUER_ENV_VAR, is_placeholder

API_MODULE = "src/api/main.py"
CONFIGURED = "https://sentinel.test-deployment.internal"


@pytest.fixture
def service(monkeypatch):
    monkeypatch.setenv(ISSUER_ENV_VAR, CONFIGURED)
    return IdentityFederationService()


def test_the_api_module_hardcodes_no_placeholder_issuer():
    source = io.open(API_MODULE, encoding="utf-8").read()
    offenders = [
        f"line {source[: match.start()].count(chr(10)) + 1}: {match.group(0)}"
        for match in re.finditer(r"https?://[A-Za-z0-9.\-]+", source)
        if is_placeholder(match.group(0))
    ]

    assert not offenders, (
        f"{API_MODULE} hardcodes a reserved documentation domain: {offenders}. "
        f"An identity provider would redirect users there. Set {ISSUER_ENV_VAR} "
        "and use the configured provider instead."
    )


def test_the_login_handlers_do_not_build_their_own_providers():
    """A locally built provider carries whatever issuer the call site names."""
    source = io.open(API_MODULE, encoding="utf-8").read()
    built = re.findall(r"\b(OIDCProvider|SAMLProvider|OAuthProvider)\s*\(", source)

    assert not built, (
        f"{API_MODULE} constructs identity providers directly: {sorted(set(built))}. "
        "Use the ones the service already configured, so the issuer comes from "
        "configuration rather than from the call site."
    )


def test_the_service_provider_follows_the_configured_issuer(service):
    assert service._oidc._issuer == CONFIGURED
    assert not is_placeholder(service._oidc._issuer)


def test_the_saml_provider_follows_the_configured_issuer(service):
    assert service._saml._sp_sso_url.startswith(CONFIGURED)
