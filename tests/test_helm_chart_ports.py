"""The Helm chart must describe the ports the application actually uses.

A container port that does not match where the process listens makes every
probe and every Service connection fail with connection refused, which reads
like a crashing image rather than a configuration mistake.
"""

import io
import re

import pytest
import yaml

VALUES = "infrastructure/helm/aegisgraph/values.yaml"
DEPLOYMENT = "infrastructure/helm/aegisgraph/templates/api-deployment.yaml"
K8S_DEPLOYMENT = "infrastructure/kubernetes/deployment.yaml"

# Lowest unprivileged port. A container with runAsNonRoot cannot bind below it.
FIRST_UNPRIVILEGED_PORT = 1024

_CONTAINER_PORTS = re.compile(r"containerPort:\s*(\{\{[^}]*\}\}|\d+)")
_TEMPLATE_REF = re.compile(r"\{\{\s*\.Values\.([A-Za-z0-9_.]+)\s*\}\}")


def _values():
    return yaml.safe_load(io.open(VALUES, encoding="utf-8").read())


def _resolve(expression, values):
    """Resolve a bare `{{ .Values.a.b }}` expression against values.yaml."""
    match = _TEMPLATE_REF.fullmatch(expression.strip().strip('"'))
    if not match:
        return expression
    node = values
    for part in match.group(1).split("."):
        node = node[part]
    return node


def _api_port_from_plain_manifest():
    """The port the plain Kubernetes manifest says the API container uses."""
    for document in yaml.safe_load_all(io.open(K8S_DEPLOYMENT, encoding="utf-8").read()):
        if not document or document.get("kind") != "Deployment":
            continue
        for container in document["spec"]["template"]["spec"]["containers"]:
            for port in container.get("ports", []):
                if port.get("name") == "http":
                    return port["containerPort"]
    raise AssertionError(f"{K8S_DEPLOYMENT} declares no named http container port")


def test_chart_container_port_matches_where_the_api_listens():
    values = _values()
    text = io.open(DEPLOYMENT, encoding="utf-8").read()
    declared = [
        _resolve(match.group(1), values) for match in _CONTAINER_PORTS.finditer(text)
    ]
    expected = _api_port_from_plain_manifest()

    assert declared, f"{DEPLOYMENT} declares no container ports"
    assert expected in declared, (
        f"the chart declares container ports {declared}, none of which is {expected}, "
        f"the port {K8S_DEPLOYMENT} says the API binds. Probes and the Service both "
        "target the named container port, so both would hit a closed port."
    )


def test_chart_container_ports_are_unprivileged():
    """The pod runs as UID 1000, which cannot bind a port below 1024."""
    values = _values()
    text = io.open(DEPLOYMENT, encoding="utf-8").read()
    privileged = [
        port
        for port in (
            _resolve(match.group(1), values)
            for match in _CONTAINER_PORTS.finditer(text)
        )
        if isinstance(port, int) and port < FIRST_UNPRIVILEGED_PORT
    ]

    assert not privileged, (
        f"the chart asks the container to listen on {privileged}, but the pod sets "
        "runAsNonRoot with runAsUser 1000 and cannot bind a privileged port"
    )


def test_service_port_and_container_port_stay_separate_values():
    """Deriving one from the other is what caused them to be wrong together."""
    values = _values()["service"]

    assert "port" in values and "targetPort" in values
    text = io.open(DEPLOYMENT, encoding="utf-8").read()

    assert ".Values.service.port" not in text, (
        "the deployment template derives a container port from service.port, "
        "which is the port the Service listens on, not the container"
    )


def test_prometheus_scrape_port_is_a_port_the_pod_exposes():
    values = _values()
    text = io.open(DEPLOYMENT, encoding="utf-8").read()
    match = re.search(r'prometheus\.io/port:\s*"([^"]+)"', text)

    assert match, "the pod template declares no prometheus scrape port"
    scrape_port = _resolve(match.group(1), values)
    exposed = [
        _resolve(found.group(1), values)
        for found in _CONTAINER_PORTS.finditer(text)
    ]

    assert scrape_port in exposed, (
        f"Prometheus is told to scrape port {scrape_port}, which the pod does not "
        f"expose. It exposes {exposed}. /metrics is served by the API itself, so "
        "the scrape port is the API port."
    )


@pytest.mark.parametrize("path", [VALUES])
def test_values_file_is_parseable_yaml(path):
    """The resolver above would silently return raw strings on a malformed file."""
    assert isinstance(yaml.safe_load(io.open(path, encoding="utf-8").read()), dict)
