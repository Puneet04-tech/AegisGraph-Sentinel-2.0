"""Every probe path in a deployment manifest must be a route the app serves.

A probe pointing at a path the application does not have returns 404 forever.
For a readiness probe that means the pod never becomes Ready, the Service never
gets an endpoint, and with maxUnavailable 0 the rollout never completes.
"""

import asyncio
import io
import re

import pytest
import yaml
from fastapi import Response
from fastapi.testclient import TestClient

import src.api.main as api_main
from src.api.main import app

MANIFESTS = [
    "infrastructure/kubernetes/deployment.yaml",
    "infrastructure/helm/aegisgraph/templates/api-deployment.yaml",
]

# Helm templates are not valid YAML on their own, so probe paths are read with a
# regex rather than a parser. Kubernetes manifests are parsed properly.
_PROBE_PATH = re.compile(
    r"(livenessProbe|readinessProbe|startupProbe):\s*\n\s*httpGet:\s*\n\s*path:\s*(\S+)"
)


def _app_paths():
    return {getattr(route, "path", None) for route in app.routes}


def _probe_paths(text):
    return [(match.group(1), match.group(2)) for match in _PROBE_PATH.finditer(text)]


@pytest.mark.parametrize("manifest", MANIFESTS)
def test_probe_paths_exist_in_the_application(manifest):
    text = io.open(manifest, encoding="utf-8").read()
    probes = _probe_paths(text)
    known = _app_paths()

    assert probes, f"{manifest} declares no HTTP probes, so this check is vacuous"

    missing = [(kind, path) for kind, path in probes if path not in known]

    assert not missing, (
        f"{manifest} probes these paths, which the application does not serve: "
        f"{missing}. A readiness probe on a missing path 404s forever, so the "
        "pod never becomes Ready."
    )


def test_kubernetes_manifest_is_parseable_yaml():
    """The regex above would silently match nothing in a malformed file."""
    documents = list(
        yaml.safe_load_all(io.open(MANIFESTS[0], encoding="utf-8").read())
    )

    assert any(doc and doc.get("kind") == "Deployment" for doc in documents)


def _call_readiness(startup_complete, monkeypatch):
    """Invoke the handler directly against a chosen startup state.

    ``api_main.state`` is a process-global that the rest of the suite mutates,
    including by entering the application lifespan, so the not-ready branch is
    exercised here rather than through a shared client.
    """
    monkeypatch.setattr(
        api_main.state, "startup_complete", startup_complete, raising=False
    )
    response = Response()
    body = asyncio.run(api_main.readiness(response))
    return response, body


def test_readiness_reports_503_before_startup_completes(monkeypatch):
    """A pod that has not finished starting must not be sent traffic."""
    response, body = _call_readiness(False, monkeypatch)

    assert response.status_code == 503
    assert body["status"] == "starting"


def test_readiness_reports_200_once_startup_is_complete(monkeypatch):
    response, body = _call_readiness(True, monkeypatch)

    assert response.status_code != 503
    assert body["status"] == "ready"


def test_the_lifespan_is_what_marks_the_service_ready(monkeypatch):
    """The flag the handler reads must actually be set by application startup."""
    monkeypatch.setattr(api_main.state, "startup_complete", False, raising=False)

    with TestClient(app) as client:
        assert api_main.state.startup_complete is True
        response = client.get("/health/readiness")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"


def test_readiness_needs_no_credentials():
    """A probe cannot present an API key, so the endpoint must stay public."""
    response = TestClient(app).get("/health/readiness")

    assert response.status_code not in (401, 403)
    assert response.status_code != 404, "the readiness route is not registered"
