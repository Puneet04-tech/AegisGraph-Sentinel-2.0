"""Pure-Python authentication helpers for the Streamlit frontend.

The API declares exactly one security scheme, an ``X-API-Key`` header, so the
dashboard identifies itself the same way rather than carrying a parallel token
model of its own.  Keeping the header construction here means it can be tested
without importing ``app.py``, whose module level Streamlit calls run on import.

Follows the same separation as :mod:`src.ui.helpers`, tracked in issue #854.
"""

from __future__ import annotations

from typing import Dict, Optional

API_KEY_HEADER = "X-API-Key"
WHOAMI_PATH = "/api/v1/auth/whoami"


def api_key_headers(
    api_key: Optional[str], extra: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    """Return request headers carrying *api_key*, merged with *extra*.

    A missing or empty key yields no auth header, so the caller receives the
    API's own 401 rather than sending an empty credential.
    """
    headers: Dict[str, str] = {}
    if api_key:
        headers[API_KEY_HEADER] = api_key
    if extra:
        headers.update(extra)
    return headers


def whoami_url(base_url: str) -> str:
    """Return the identity endpoint URL for *base_url*."""
    return f"{base_url.rstrip('/')}{WHOAMI_PATH}"
