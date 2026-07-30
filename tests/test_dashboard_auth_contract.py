"""The dashboard must authenticate the way the API actually works.

``app.py`` is a Streamlit script whose module level code runs on import, so it
cannot be imported by a test. These checks therefore work two ways: they
exercise the extracted helpers directly, and they read the script's source to
confirm the URLs it builds exist and the header it sends is the one the API
declares.
"""

import ast
import hashlib
import io
import re

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.security import Role, _invalidate_auth_cache
from src.ui.auth import API_KEY_HEADER, WHOAMI_PATH, api_key_headers, whoami_url

DASHBOARD = "app.py"


@pytest.fixture
def keyed_client(monkeypatch):
    """Client with one distinct API key configured per role."""
    keys = {role: f"dashboard-contract-{role.value.lower()}" for role in Role}
    for role, key in keys.items():
        monkeypatch.setenv(
            f"AEGIS_ROLE_{role.value}", hashlib.sha256(key.encode()).hexdigest()
        )
    _invalidate_auth_cache()
    yield TestClient(app), keys
    _invalidate_auth_cache()


def _dashboard_source():
    return io.open(DASHBOARD, encoding="utf-8").read()


def test_whoami_rejects_an_anonymous_caller(keyed_client):
    client, _ = keyed_client

    assert client.get(WHOAMI_PATH).status_code == 401


def test_whoami_rejects_an_unknown_key(keyed_client):
    client, _ = keyed_client

    response = client.get(WHOAMI_PATH, headers={API_KEY_HEADER: "not-a-real-key"})

    assert response.status_code == 401


@pytest.mark.parametrize("role", list(Role))
def test_whoami_reports_the_role_behind_the_key(keyed_client, role):
    client, keys = keyed_client

    response = client.get(WHOAMI_PATH, headers={API_KEY_HEADER: keys[role]})

    assert response.status_code == 200
    assert response.json() == {"role": role.value}


def test_whoami_declares_its_security_requirement():
    """Otherwise the dashboard is documented as able to call it anonymously."""
    operation = app.openapi()["paths"][WHOAMI_PATH]["get"]

    assert operation.get("security"), (
        "the identity endpoint enforces auth but declares none, so a generated "
        "client would omit the key"
    )


def test_api_key_headers_uses_the_declared_scheme():
    scheme = app.openapi()["components"]["securitySchemes"]["APIKeyHeader"]

    assert scheme["name"] == API_KEY_HEADER
    assert api_key_headers("abc") == {API_KEY_HEADER: "abc"}


def test_api_key_headers_merges_extras_and_skips_an_empty_key():
    assert api_key_headers("abc", {"X-Honeypot-Token": "t"}) == {
        API_KEY_HEADER: "abc",
        "X-Honeypot-Token": "t",
    }
    assert api_key_headers(None) == {}
    assert api_key_headers("") == {}


def test_whoami_url_joins_without_a_doubled_slash():
    assert whoami_url("http://127.0.0.1:8000") == f"http://127.0.0.1:8000{WHOAMI_PATH}"
    assert whoami_url("http://127.0.0.1:8000/") == f"http://127.0.0.1:8000{WHOAMI_PATH}"


def test_dashboard_does_not_send_a_bearer_token():
    """The API declares no bearer scheme, so a bearer header authenticates nothing."""
    source = _dashboard_source()

    assert "Bearer " not in source, (
        "app.py builds an Authorization: Bearer header, which the API does not "
        "accept. It declares only the X-API-Key scheme."
    )


def test_every_api_path_in_the_dashboard_is_a_route_the_app_serves():
    """A literal path that no route matches is a request that can only 404."""
    patterns = [
        re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", route.path) + "$")
        for route in app.routes
        if isinstance(route, APIRoute)
    ]
    tree = ast.parse(_dashboard_source())
    unmatched = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        if any(not isinstance(value, ast.Constant) for value in node.values[1:]):
            # An interpolated segment, so the literal prefix alone proves nothing.
            continue
        text = "".join(
            value.value for value in node.values if isinstance(value, ast.Constant)
        )
        match = re.search(r"/api/v1/[^\s\"'?]+", text)
        if match and not any(p.match(match.group(0)) for p in patterns):
            unmatched.append((node.lineno, match.group(0)))

    assert not unmatched, (
        f"{DASHBOARD} builds API paths the application does not serve: "
        f"{unmatched}. Every one of these can only return 404."
    )
