"""The tenant a request is acting for, resolved from its authentication.

Deriving a tenant by string-splitting the API key makes the secret carry the
identity, and gives every key that does not match the expected shape the same
fallback tenant. The application already resolves tenants properly in
``TenantIsolationMiddleware``, from a JWT claim, an ``X-Tenant-ID`` header
checked against the credential, or ``AEGIS_API_KEY_TENANT_MAP``, and binds the
result to the request context. This exposes that value as a dependency.

The fallback exists for a router mounted without the middleware, as the phase
module test suites do. It derives a tenant from the key hash rather than from
the key text, so two different keys never share one tenant by accident.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from fastapi import HTTPException, Security, status

from src.api.middleware.multi_tenancy import get_current_tenant
from src.api.security import api_key_header


def tenant_for_key(api_key: str) -> str:
    """Return a stable tenant identifier derived from *api_key*.

    Matches the derived form ``TenantIsolationMiddleware`` uses when no tenant
    map is configured, so both paths agree on the same key.
    """
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    return f"api_{digest[:24]}"


def resolve_tenant(
    x_api_key: Optional[str] = Security(api_key_header),
) -> str:
    """FastAPI dependency returning the tenant the caller may act for."""
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key"
        )

    resolved = get_current_tenant()
    if resolved:
        return resolved

    return tenant_for_key(x_api_key)
