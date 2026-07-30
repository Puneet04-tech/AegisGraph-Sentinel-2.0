"""The Content-Security-Policy must not block the documentation it ships with.

FastAPI generates the Swagger UI and ReDoc pages with their bundles loaded from
a CDN. A same-origin policy blocks those scripts, and both pages render blank in
any compliant browser while still returning 200, so nothing notices.
"""

import re
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.middleware.security_headers import _CSP_VALUE

DOCS_PATHS = ["/docs", "/redoc"]
API_PATH = "/api/v1/health"

_URL = re.compile(r'https?://[^"\'\s>)]+')


def _client():
    return TestClient(app)


def _directives(policy):
    parsed = {}
    for chunk in policy.split(";"):
        chunk = chunk.strip()
        if chunk:
            parts = chunk.split()
            parsed[parts[0]] = parts[1:]
    return parsed


def _directive_for(url):
    if url.endswith(".js"):
        return "script-src"
    if url.endswith(".css") or "fonts.googleapis" in url:
        return "style-src"
    return "img-src"


def _origin(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


@pytest.mark.parametrize("path", DOCS_PATHS)
def test_documentation_page_assets_are_not_blocked_by_its_own_csp(path):
    response = _client().get(path)

    assert response.status_code == 200, f"{path} did not render at all"

    policy = response.headers.get("Content-Security-Policy", "")
    assert policy, f"{path} carries no Content-Security-Policy"
    directives = _directives(policy)

    blocked = []
    for url in sorted(set(_URL.findall(response.text))):
        directive = _directive_for(url)
        allowed = directives.get(directive, directives.get("default-src", []))
        if _origin(url) not in allowed:
            blocked.append((directive, url))

    assert not blocked, (
        f"{path} loads these resources, which its own CSP forbids: {blocked}. "
        "A browser blocks them and the page renders blank while still "
        "returning 200."
    )


@pytest.mark.parametrize("path", DOCS_PATHS)
def test_documentation_page_actually_references_external_assets(path):
    """If FastAPI stopped using a CDN, the check above would be vacuous."""
    response = _client().get(path)

    assert _URL.findall(response.text), (
        f"{path} references no external URLs, so the CSP check proves nothing"
    )


def test_api_responses_keep_the_strict_policy():
    """Only the documentation paths may relax the policy."""
    response = _client().get(API_PATH)

    assert response.headers.get("Content-Security-Policy") == _CSP_VALUE


def test_the_relaxed_policy_is_not_a_wildcard():
    """Naming origins is the point; a wildcard would defeat it."""
    policy = _client().get("/docs").headers.get("Content-Security-Policy", "")

    assert "*" not in policy, f"the documentation policy contains a wildcard: {policy}"
    assert "'unsafe-eval'" not in policy
    assert "frame-ancestors 'none'" in policy
    assert "object-src 'none'" in policy
