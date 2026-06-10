"""Tests for SecurityHeadersMiddleware (Issue #1086).

Verifies that every API response carries the required OWASP defensive headers
and that the HSTS toggle behaves correctly.
"""

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from src.api.middleware.security_headers import SecurityHeadersMiddleware


def _make_app(hsts: bool = True) -> Starlette:
    async def homepage(request: Request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/", homepage)])
    app.add_middleware(SecurityHeadersMiddleware, hsts=hsts)
    return app


class TestSecurityHeadersPresent:
    def setup_method(self):
        self.client = TestClient(_make_app(hsts=True))
        self.response = self.client.get("/")

    def test_x_content_type_options(self):
        assert self.response.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self):
        assert self.response.headers.get("x-frame-options") == "DENY"

    def test_referrer_policy(self):
        assert self.response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_x_xss_protection(self):
        assert self.response.headers.get("x-xss-protection") == "1; mode=block"

    def test_strict_transport_security_present_when_enabled(self):
        hsts = self.response.headers.get("strict-transport-security", "")
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts

    def test_content_security_policy_present(self):
        csp = self.response.headers.get("content-security-policy", "")
        assert "default-src" in csp
        assert "frame-ancestors 'none'" in csp


class TestHstsToggle:
    def test_hsts_absent_when_disabled(self):
        client = TestClient(_make_app(hsts=False))
        response = client.get("/")
        assert "strict-transport-security" not in response.headers

    def test_hsts_present_when_enabled(self):
        client = TestClient(_make_app(hsts=True))
        response = client.get("/")
        assert "strict-transport-security" in response.headers


class TestHeadersOnErrorResponses:
    def test_headers_present_on_404(self):
        client = TestClient(_make_app(), raise_server_exceptions=False)
        response = client.get("/nonexistent")
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("x-frame-options") == "DENY"
