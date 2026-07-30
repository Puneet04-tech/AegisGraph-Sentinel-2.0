"""Every route that takes an API key must read the X-API-Key header.

FastAPI derives a header name from the parameter name when no alias is given,
so a parameter called api_key reads a header called api-key. The documented
header, the one the Streamlit UI sends and the one declared as the OpenAPI
security scheme, is X-API-Key, so such a route cannot be called as documented.
"""

import ast
import glob
import hashlib
import io

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.security import _invalidate_auth_cache

AGENT_ENDPOINT = "/api/v1/agents/stats"
VALID_KEY = "agent-header-test-key"


@pytest.fixture(autouse=True)
def _analyst_key_configured(monkeypatch):
    digest = hashlib.sha256(VALID_KEY.encode()).hexdigest()
    monkeypatch.setenv("AEGIS_ROLE_ANALYST", digest)
    monkeypatch.setenv("AEGIS_API_KEY_HASHES", digest)
    _invalidate_auth_cache()
    yield
    _invalidate_auth_cache()


def _header_params():
    """Yield (file, function, parameter, derived header) for Header() params."""
    for path in sorted(glob.glob("src/api/*_routes.py")):
        tree = ast.parse(io.open(path, encoding="utf-8", errors="replace").read())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = node.args.args + node.args.kwonlyargs
            defaults = list(node.args.defaults) + [
                d for d in node.args.kw_defaults if d
            ]
            if not defaults:
                continue
            for arg, default in zip(args[-len(defaults):], defaults):
                if not (
                    isinstance(default, ast.Call)
                    and getattr(default.func, "id", "") == "Header"
                ):
                    continue
                alias = None
                for keyword in default.keywords:
                    if keyword.arg == "alias":
                        try:
                            alias = ast.literal_eval(keyword.value)
                        except Exception:
                            alias = "<expr>"
                yield path, node.name, arg.arg, alias or arg.arg.replace("_", "-")


def test_no_route_reads_an_api_key_from_a_non_standard_header():
    """A parameter that carries an API key must resolve to X-API-Key."""
    wrong = [
        (path, fn, param, header)
        for path, fn, param, header in _header_params()
        if "api_key" in param.lower() and header.lower() != "x-api-key"
    ]

    assert not wrong, (
        "These handlers take an API key from a header other than X-API-Key, so "
        f"they cannot be called as documented: {wrong}. Add "
        'alias="X-API-Key" to the Header() declaration.'
    )


def test_agent_endpoint_accepts_the_documented_header():
    response = TestClient(app).get(
        AGENT_ENDPOINT, headers={"X-API-Key": VALID_KEY}
    )

    assert response.status_code == 200, (
        f"{AGENT_ENDPOINT} rejected the documented X-API-Key header"
    )


def test_agent_endpoint_rejects_a_wrong_key():
    response = TestClient(app).get(
        AGENT_ENDPOINT, headers={"X-API-Key": "not-the-configured-key"}
    )

    assert response.status_code == 401


def test_agent_endpoint_rejects_a_missing_key():
    response = TestClient(app).get(AGENT_ENDPOINT)

    assert response.status_code == 401


def test_agent_endpoint_ignores_the_previous_header_name():
    """The old api-key header must no longer authenticate on its own."""
    response = TestClient(app).get(AGENT_ENDPOINT, headers={"api-key": VALID_KEY})

    assert response.status_code == 401
