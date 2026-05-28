"""API authentication helpers.

Centralised key-based authentication for AegisGraph Sentinel 2.0's HTTP
surface. Keys are stored server-side as SHA-256 hashes rather than
plaintext, matching the convention already established by
``_require_honeypot_admin`` and the legal-export endpoint in
``src.api.main``. The plaintext key is never written to disk or read
from configuration; only the hash is.

Usage in route definitions::

    from fastapi import Depends
    from .security import require_api_key

    @app.post(
        "/api/v1/fraud/check",
        dependencies=[Depends(require_api_key)],
    )
    async def check_transaction(...):
        ...

Operators configure the service by exporting ``AEGIS_API_KEY_HASHES`` as
a comma-separated list of lowercase hex SHA-256 hashes. See ``SECURITY.md``
for the full operator playbook.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Annotated, List, Optional

from fastapi import Header, HTTPException, status

# Environment variable read on every request. The cost is one
# ``os.getenv`` and a split — well under a microsecond per call — and
# keeping the read inline means key rotation only requires updating the
# env and restarting workers, not bouncing the whole process.
_ENV_VAR = "AEGIS_API_KEY_HASHES"


def _load_allowed_hashes() -> List[str]:
    """Return the list of configured SHA-256 hashes, lowercased.

    Empty list means the gate is not configured; the dependency treats
    this as a fail-closed condition rather than allowing traffic
    through, so an operator who forgets the env var sees 503s
    immediately rather than silently exposing endpoints.
    """
    raw = os.getenv(_ENV_VAR, "").strip()
    if not raw:
        return []
    return [chunk.strip().lower() for chunk in raw.split(",") if chunk.strip()]


def require_api_key(
    x_api_key: Annotated[Optional[str], Header(alias="X-API-Key")] = None,
) -> None:
    """FastAPI dependency that gates a route behind an API key check.

    The incoming ``X-API-Key`` header value is hashed with SHA-256 and
    compared against every entry in ``AEGIS_API_KEY_HASHES`` using
    ``hmac.compare_digest`` to avoid timing oracles. A match anywhere
    in the list permits the request.

    Multiple hashes are supported specifically so that operators can
    rotate keys without downtime: add the new hash to the env var
    alongside the old one, restart, distribute the new key, then
    remove the old hash after clients have switched.

    Raises:
        HTTPException 503: ``AEGIS_API_KEY_HASHES`` is unset or empty.
            The service is misconfigured; refuse traffic rather than
            allow it through. This mirrors the fail-closed posture of
            ``_require_honeypot_admin`` in ``src.api.main``.
        HTTPException 401: the ``X-API-Key`` header is missing.
        HTTPException 403: the header is present but its hash does
            not match any allowed hash.
    """
    allowed_hashes = _load_allowed_hashes()
    if not allowed_hashes:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"API key authentication is not configured. Set the "
                f"{_ENV_VAR} environment variable to a comma-separated "
                "list of lowercase hex SHA-256 hashes before serving "
                "traffic. See SECURITY.md for the operator playbook."
            ),
        )

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )

    provided_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
    for allowed_hash in allowed_hashes:
        if hmac.compare_digest(provided_hash, allowed_hash):
            return None

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid API key",
    )