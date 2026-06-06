"""API authentication helpers with Role-Based Access Control (RBAC).

Centralised key-based authentication and role-aware authorization for
AegisGraph Sentinel 2.0's HTTP surface. Keys are stored server-side as
SHA-256 hashes rather than plaintext.

Usage in route definitions::

    from fastapi import Depends
    from .security import Role, require_role

    @app.post(
        "/api/v1/fraud/check",
        dependencies=[Depends(require_role(Role.ANALYST))],
    )
    async def check_transaction(...):
        ...

Operators configure the service by exporting:
- ``AEGIS_API_KEY_HASHES``: comma-separated list of SHA-256 hashes (default to SUPER_ADMIN for backward compatibility)
- ``AEGIS_ROLE_<ROLE_NAME>``: role-specific API key hashes. e.g. ``AEGIS_ROLE_SUPER_ADMIN``
"""

from __future__ import annotations

import hashlib
import hmac
import os
from enum import Enum
from typing import Annotated, List, Optional

from fastapi import Header, HTTPException, status


class Role(str, Enum):
    """Supported authorization roles."""
    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"


# Defines role hierarchies and inheritance.
# A key with a given role has access to all roles in its inherited set.
ROLE_INHERITANCE = {
    Role.SUPER_ADMIN: {Role.SUPER_ADMIN, Role.ADMIN, Role.ANALYST, Role.AUDITOR, Role.VIEWER},
    Role.ADMIN: {Role.ADMIN, Role.ANALYST, Role.AUDITOR, Role.VIEWER},
    Role.ANALYST: {Role.ANALYST, Role.VIEWER},
    Role.AUDITOR: {Role.AUDITOR, Role.VIEWER},
    Role.VIEWER: {Role.VIEWER},
}

_ENV_VAR = "AEGIS_API_KEY_HASHES"


def _load_allowed_hashes() -> List[str]:
    """Return the list of configured general SHA-256 hashes, lowercased."""
    raw = os.getenv(_ENV_VAR, "").strip()
    if not raw:
        return []
    return [chunk.strip().lower() for chunk in raw.split(",") if chunk.strip()]


def _load_role_hashes(role: Role) -> List[str]:
    """Return the list of configured role-specific SHA-256 hashes, lowercased."""
    env_var = f"AEGIS_ROLE_{role.value}"
    raw = os.getenv(env_var, "").strip()
    if not raw:
        return []
    return [chunk.strip().lower() for chunk in raw.split(",") if chunk.strip()]


def _is_configured() -> bool:
    """Return True if any API key hashes are configured."""
    if _load_allowed_hashes():
        return True
    for role in Role:
        if _load_role_hashes(role):
            return True
    return False


def _get_key_role(api_key: str) -> Optional[Role]:
    """Identify the role assigned to the provided API key using constant-time comparison."""
    provided_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    # Search role-specific maps first
    for role in Role:
        role_hashes = _load_role_hashes(role)
        for allowed_hash in role_hashes:
            if hmac.compare_digest(provided_hash, allowed_hash):
                return role

    # Fallback to general allowed hashes, mapping to SUPER_ADMIN role for backward compatibility
    general_hashes = _load_allowed_hashes()
    for allowed_hash in general_hashes:
        if hmac.compare_digest(provided_hash, allowed_hash):
            return Role.SUPER_ADMIN

    return None


def require_api_key(
    x_api_key: Annotated[Optional[str], Header(alias="X-API-Key")] = None,
) -> None:
    """FastAPI dependency that gates a route behind a generic API key check.

    Preserved for backward compatibility. Checks general and role-specific keys.

    Raises:
        HTTPException 503: No API keys configured.
        HTTPException 401: X-API-Key header missing.
        HTTPException 403: Invalid API key.
    """
    if not _is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"API key authentication is not configured. Set the "
                f"{_ENV_VAR} or role-specific environment variables to a "
                "comma-separated list of lowercase hex SHA-256 hashes."
            ),
        )

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )

    role = _get_key_role(x_api_key)
    if role is not None:
        return None

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid API key",
    )


def require_role(*allowed_roles: Role):
    """FastAPI dependency factory that gates a route based on RBAC roles and inheritance.

    Authentication is enforced via constant-time HMAC comparison of the SHA-256
    hash of the provided ``X-API-Key`` header against the server-side configured
    hashes.  There is no bypass path — this function is O(K) where K is the
    number of configured API key hashes, independent of the number of loaded
    Python modules.

    Test suites should use ``app.dependency_overrides`` at the ``TestClient``
    level, which has no effect on this function.

    Raises:
        HTTPException 503: No API keys configured.
        HTTPException 401: Missing or invalid API key.
        HTTPException 403: Insufficient permissions for the requested role.
    """
    def dependency(
        x_api_key: Annotated[Optional[str], Header(alias="X-API-Key")] = None,
    ) -> Role:
        if not _is_configured():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API key authentication is not configured.",
            )

        if not x_api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-API-Key header",
            )

        role = _get_key_role(x_api_key)
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )

        has_access = any(
            allowed in ROLE_INHERITANCE.get(role, set())
            for allowed in allowed_roles
        )
        if not has_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this operation",
            )

        return role

    return dependency