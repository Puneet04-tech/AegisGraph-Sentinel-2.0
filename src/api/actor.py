"""Who performed an action, derived from the credential that authenticated it.

An audit trail is only worth keeping if the actor it names is the one that acted.
Taking the actor from a request header lets any caller write any name into the
record, so the identity here is bound to the API key the request presented.

Operators who want human readable names in the trail map each key to one:

    AEGIS_API_KEY_ANALYST_MAP="<sha256-of-key>=priya.n,<sha256-of-key>=sam.o"

which mirrors ``AEGIS_API_KEY_TENANT_MAP`` in the tenancy middleware. An
unmapped key still gets a stable identifier derived from its hash, so actions
remain attributable to a credential even before anyone fills the map in.
"""

from __future__ import annotations

import hashlib
import os
from typing import Dict, Optional

from fastapi import Security

from src.api.security import api_key_header

ANALYST_MAP_ENV_VAR = "AEGIS_API_KEY_ANALYST_MAP"

# Recorded when a request carries no key at all. Routes using this dependency
# are gated by require_role, so this should not occur in production; it exists
# so the audit trail never silently attributes an action to a real name.
UNIDENTIFIED_ACTOR = "unidentified"


def _load_analyst_map() -> Dict[str, str]:
    """Return the configured key hash to analyst id mapping, lowercased."""
    raw = os.getenv(ANALYST_MAP_ENV_VAR, "").strip()
    if not raw:
        return {}

    mapping: Dict[str, str] = {}
    for entry in raw.split(","):
        chunk = entry.strip()
        if not chunk or "=" not in chunk:
            continue
        key_hash, analyst_id = chunk.split("=", 1)
        analyst_id = analyst_id.strip()
        if analyst_id:
            mapping[key_hash.strip().lower()] = analyst_id
    return mapping


def analyst_id_for_key(api_key: Optional[str]) -> str:
    """Return the analyst identity bound to *api_key*."""
    if not api_key:
        return UNIDENTIFIED_ACTOR

    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    mapped = _load_analyst_map().get(digest)
    if mapped:
        return mapped
    return f"api_{digest[:24]}"


def resolve_analyst_id(
    x_api_key: Optional[str] = Security(api_key_header),
) -> str:
    """FastAPI dependency returning the actor for the authenticated caller."""
    return analyst_id_for_key(x_api_key)
