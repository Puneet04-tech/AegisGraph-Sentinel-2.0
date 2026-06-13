"""HTTP security response headers middleware.

Adds the standard set of defensive HTTP headers to every API response,
addressing OWASP A05:2021 — Security Misconfiguration.

Headers applied
---------------
``X-Content-Type-Options: nosniff``
    Prevents browsers from MIME-sniffing a response away from its declared
    Content-Type.  Without this, a browser receiving a JSON response might
    interpret it as HTML in certain contexts, enabling injection attacks.

``X-Frame-Options: DENY``
    Prevents the API or any downstream iframe-embedded UI from being framed
    by a third-party page, blocking clickjacking attacks.

``Strict-Transport-Security: max-age=31536000; includeSubDomains``
    Instructs browsers to connect only over HTTPS for the next year.
    Critical for a platform handling financial transaction data.

``Referrer-Policy: strict-origin-when-cross-origin``
    Limits referrer information sent to third-party origins, preventing
    transaction IDs or case numbers from leaking via the Referer header.

``X-XSS-Protection: 1; mode=block``
    Activates the XSS filter built into older browsers and instructs them
    to block the page rather than sanitise it.

``Content-Security-Policy``
    Baseline CSP that restricts resource loading to same-origin, with
    explicit opt-in for the Swagger UI inline scripts.  Deployments should
    tighten this further for their specific front-end origins.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp


# The HSTS header must only be sent over HTTPS connections.  We skip it on
# plain HTTP (e.g. local dev) to avoid breaking non-TLS development setups.
_HSTS_VALUE = "max-age=31536000; includeSubDomains"

# Baseline CSP — same-origin only, with script-src allowing the inline
# scripts that FastAPI's Swagger UI injects.  Tighten in production.
_CSP_VALUE = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "frame-ancestors 'none';"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that adds HTTP security headers to every response.

    Register it after ``CORSMiddleware`` so CORS preflight responses also
    carry the security headers::

        app.add_middleware(SecurityHeadersMiddleware)

    The middleware is intentionally unopinionated — it sets conservative
    defaults that are safe for all environments.  Individual deployments can
    sub-class and override ``_get_headers()`` to adjust values.
    """

    def __init__(self, app: ASGIApp, hsts: bool = True) -> None:
        super().__init__(app)
        self._hsts = hsts

    def _get_headers(self) -> dict:
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": _CSP_VALUE,
        }
        if self._hsts:
            headers["Strict-Transport-Security"] = _HSTS_VALUE
        return headers

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for header, value in self._get_headers().items():
            response.headers[header] = value
        return response
