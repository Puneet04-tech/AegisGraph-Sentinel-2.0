"""An unrecognised filter must not widen the result set.

`get_decision_history` coerced `decision_type` to an enum and swallowed the
ValueError, leaving the filter as None. A caller asking for one type of decision
received every decision instead, with a 200 and nothing to indicate the filter
had been discarded.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.security import _invalidate_auth_cache
from src.api.validators import reset_rate_limiter
from src.decision_fabric import DecisionType

API_KEY = "decision-filter-test-key"
HISTORY = "/api/v1/decision/history"
NOT_A_TYPE = "TOTALLY_NOT_A_DECISION_TYPE"


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    digest = hashlib.sha256(API_KEY.encode()).hexdigest()
    monkeypatch.setenv("AEGIS_ROLE_SUPER_ADMIN", digest)
    _invalidate_auth_cache()
    reset_rate_limiter()
    yield
    reset_rate_limiter()
    _invalidate_auth_cache()


@pytest.fixture
def seeded_client():
    """Two decisions of different types, so a filter has something to remove."""
    client = TestClient(app)
    headers = {"X-API-Key": API_KEY}
    for decision_type in list(DecisionType)[:2]:
        response = client.post(
            "/api/v1/decision/evaluate",
            headers=headers,
            json={"decision_type": decision_type.value, "context": {"probe": 1}},
        )
        assert response.status_code == 200, response.text[:150]
    return client, headers


def _history(client, headers, decision_type=None):
    url = HISTORY if decision_type is None else f"{HISTORY}?decision_type={decision_type}"
    return client.get(url, headers=headers)


def test_an_unrecognised_decision_type_is_rejected(seeded_client):
    client, headers = seeded_client
    unfiltered = _history(client, headers).json()["count"]

    response = _history(client, headers, NOT_A_TYPE)

    assert response.status_code != 200 or response.json()["count"] != unfiltered, (
        f"an unrecognised decision_type returned all {unfiltered} decisions, so "
        "the filter was silently discarded"
    )
    assert response.status_code == 400


def test_a_valid_decision_type_still_filters(seeded_client):
    client, headers = seeded_client
    wanted = list(DecisionType)[0].value

    unfiltered = _history(client, headers).json()["count"]
    filtered = _history(client, headers, wanted).json()

    assert filtered["count"] < unfiltered, "the valid filter removed nothing"
    assert all(d["decision_type"] == wanted for d in filtered["decisions"])


def test_no_filter_still_returns_everything(seeded_client):
    client, headers = seeded_client

    response = _history(client, headers)

    assert response.status_code == 200
    assert response.json()["count"] >= 2


def test_the_rejection_matches_the_sibling_endpoints(seeded_client):
    """evaluate and recommend already 400 on the same value; history now agrees."""
    client, headers = seeded_client

    evaluate = client.post(
        "/api/v1/decision/evaluate",
        headers=headers,
        json={"decision_type": NOT_A_TYPE, "context": {}},
    )
    history = _history(client, headers, NOT_A_TYPE)

    assert evaluate.status_code == 400
    assert history.status_code == evaluate.status_code, (
        "the same invalid value is a client error on /evaluate but not on "
        "/history, so one module reports the same mistake two ways"
    )
