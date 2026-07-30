"""Where this deployment tells identity providers to send users back to.

Every federated flow hands an external identity provider a URL on this service:
the OIDC ``redirect_uri`` and the SAML AssertionConsumerService and SingleLogout
endpoints. Those URLs have to name the host actually serving the API, so the
value is read from the environment rather than compiled in.
"""

from __future__ import annotations

import os

ISSUER_ENV_VAR = "AEGIS_IDENTITY_ISSUER"

# Matches the API URL the rest of the project defaults to for a local run, so a
# developer who has not set anything gets a URL pointing at their own service
# rather than at a domain nobody controls.
DEFAULT_ISSUER = "http://127.0.0.1:8000"

# Reserved for documentation by RFC 2606. A deployment that advertises this is
# telling identity providers to redirect users somewhere it does not own.
PLACEHOLDER_HOSTS = ("example.com", "example.org", "example.net")


def default_issuer() -> str:
    """Return the configured issuer, without a trailing slash."""
    configured = os.getenv(ISSUER_ENV_VAR, "").strip()
    return (configured or DEFAULT_ISSUER).rstrip("/")


def is_placeholder(issuer: str) -> bool:
    """Return True if *issuer* names a reserved documentation domain."""
    lowered = issuer.lower()
    return any(host in lowered for host in PLACEHOLDER_HOSTS)
