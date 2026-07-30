"""Federated flows must hand identity providers this deployment's own host.

The OIDC redirect_uri and the SAML AssertionConsumerService and SingleLogout
URLs are sent to an external identity provider, which then sends the user, and
for SAML the signed assertion, back to whatever they name. They were compiled in
as aegisgraph.example.com, a domain reserved for documentation that no
deployment owns.
"""

import io
import pathlib
import re

import pytest

from src.identity_federation import IdentityFederationService
from src.identity_federation.issuer import (
    DEFAULT_ISSUER,
    ISSUER_ENV_VAR,
    default_issuer,
    is_placeholder,
)

PACKAGE = pathlib.Path("src/identity_federation")
CONFIGURED = "https://sentinel.test-deployment.internal"


@pytest.fixture
def service(monkeypatch):
    monkeypatch.setenv(ISSUER_ENV_VAR, CONFIGURED)
    return IdentityFederationService()


def test_default_issuer_reads_the_environment(monkeypatch):
    monkeypatch.setenv(ISSUER_ENV_VAR, "https://configured.internal/")

    assert default_issuer() == "https://configured.internal"


def test_default_issuer_falls_back_to_the_local_api(monkeypatch):
    monkeypatch.delenv(ISSUER_ENV_VAR, raising=False)

    assert default_issuer() == DEFAULT_ISSUER
    assert not is_placeholder(DEFAULT_ISSUER), (
        "the fallback names a reserved documentation domain, which is the "
        "defect this is meant to prevent"
    )


def test_saml_assertion_consumer_url_follows_the_configured_issuer(service):
    assert service._saml._sp_sso_url == f"{CONFIGURED}/api/v1/identity/saml/acs"


def test_saml_logout_url_follows_the_configured_issuer(service):
    assert service._saml._sp_slo_url == f"{CONFIGURED}/api/v1/identity/saml/slo"


def test_oidc_redirect_uri_follows_the_configured_issuer(service):
    assert service._oidc._issuer == CONFIGURED


def test_no_federation_url_points_at_a_reserved_domain(service):
    advertised = [
        service._issuer,
        service._saml._sp_sso_url,
        service._saml._sp_slo_url,
        service._oidc._issuer,
        service._oauth._issuer,
    ]
    placeholders = [url for url in advertised if is_placeholder(url)]

    assert not placeholders, (
        f"these URLs are handed to external identity providers and name a "
        f"reserved documentation domain: {placeholders}"
    )


def test_the_package_hardcodes_no_placeholder_host():
    """A compiled-in default would survive any amount of configuration."""
    offenders = []
    for path in sorted(PACKAGE.glob("*.py")):
        text = io.open(path, encoding="utf-8", errors="replace").read()
        for match in re.finditer(r"https?://[A-Za-z0-9.\-]+", text):
            url = match.group(0)
            if is_placeholder(url) and path.name != "issuer.py":
                line = text[: match.start()].count("\n") + 1
                offenders.append(f"{path.name}:{line} {url}")

    assert not offenders, (
        f"these hardcode a reserved documentation domain: {offenders}. "
        f"Set {ISSUER_ENV_VAR} and derive the URL from it instead."
    )
