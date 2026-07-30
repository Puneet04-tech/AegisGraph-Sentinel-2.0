"""Metric labels must come from the route, not from the URL a caller chose.

Labelling by ``request.url.path`` gives every distinct id and every mistyped
path its own time series. The registry lives for the process lifetime, so any
caller, authenticated or not, can grow it without bound and multiply the series
Prometheus has to store.
"""

import hashlib
import re

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.security import _invalidate_auth_cache
from src.api.validators import reset_rate_limiter

API_KEY = "metrics-cardinality-test-key"
PARAMETERISED_ROUTE = "/api/v1/cases/{case_id}"
UNMATCHED_ENDPOINT_LABEL = "unmatched"
# Scraping /metrics is itself a request, so its own series appears on the next
# scrape and is not part of what a test caused.
SELF_LABELS = {"/metrics"}

_SERIES = re.compile(r'aegis_api_latency_seconds_count\{endpoint="([^"]*)"')


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    digest = hashlib.sha256(API_KEY.encode()).hexdigest()
    for role in ("ANALYST", "ADMIN", "SUPER_ADMIN"):
        monkeypatch.setenv(f"AEGIS_ROLE_{role}", digest)
    _invalidate_auth_cache()
    reset_rate_limiter()
    yield
    reset_rate_limiter()
    _invalidate_auth_cache()


def _labels(client):
    return set(_SERIES.findall(client.get("/metrics").text)) - SELF_LABELS


def test_distinct_ids_share_one_series():
    client = TestClient(app)
    headers = {"X-API-Key": API_KEY}

    before = _labels(client)
    for index in range(12):
        reset_rate_limiter()
        client.get(f"/api/v1/cases/CASE_{index:06d}", headers=headers)
    new = _labels(client) - before

    assert new <= {PARAMETERISED_ROUTE}, (
        f"12 requests to the same route with different ids created {len(new)} "
        f"time series: {sorted(new)}. The label is the raw path, so a caller "
        "can grow the registry without bound."
    )


def test_unmatched_paths_share_one_series():
    """404s need no credentials, so this is reachable by anyone."""
    client = TestClient(app)

    before = _labels(client)
    for index in range(12):
        reset_rate_limiter()
        client.get(f"/no-such-route-{index}")
    new = _labels(client) - before

    assert new <= {UNMATCHED_ENDPOINT_LABEL}, (
        f"12 unmatched paths created {len(new)} time series: {sorted(new)}"
    )


def test_a_matched_route_is_still_labelled_with_its_template():
    """Bounding the labels must not reduce them all to one bucket."""
    client = TestClient(app)
    headers = {"X-API-Key": API_KEY}

    client.get("/api/v1/cases/CASE_LABELLED", headers=headers)

    assert PARAMETERISED_ROUTE in _labels(client), (
        "the parameterised route lost its own series, so per endpoint latency "
        "is no longer observable"
    )


def test_the_label_is_never_a_concrete_id():
    client = TestClient(app)
    headers = {"X-API-Key": API_KEY}

    client.get("/api/v1/cases/CASE_UNIQUE_MARKER", headers=headers)

    leaked = [label for label in _labels(client) if "CASE_UNIQUE_MARKER" in label]

    assert not leaked, f"a request id reached a metric label: {leaked}"
