"""The case audit trail must name the credential that acted.

Every mutating case route took its actor from an `X-Analyst-ID` request header
with a default of "system", so one key could write any name into the trail and
two actions from the same caller could appear as two different analysts.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from src.api.actor import (
    ANALYST_MAP_ENV_VAR,
    UNIDENTIFIED_ACTOR,
    analyst_id_for_key,
)
from src.api.main import app
from src.api.security import _invalidate_auth_cache
from src.api.validators import reset_rate_limiter

KEY_ONE = "case-actor-test-key-one"
KEY_TWO = "case-actor-test-key-two"
DIGEST_TWO = hashlib.sha256(KEY_TWO.encode()).hexdigest()
MAPPED_NAME = "priya.n"

CASE_BODY = {
    "transaction_id": "TXN_ACTOR_TEST",
    "risk_score": 0.95,
    "decision": "BLOCK",
    "priority": "HIGH",
}


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    digests = ",".join(
        hashlib.sha256(key.encode()).hexdigest() for key in (KEY_ONE, KEY_TWO)
    )
    for role in ("ANALYST", "ADMIN", "SUPER_ADMIN"):
        monkeypatch.setenv(f"AEGIS_ROLE_{role}", digests)
    monkeypatch.setenv(ANALYST_MAP_ENV_VAR, f"{DIGEST_TWO}={MAPPED_NAME}")
    _invalidate_auth_cache()
    reset_rate_limiter()
    yield
    reset_rate_limiter()
    _invalidate_auth_cache()


def _open_case(client, key, claimed_name=None):
    headers = {"X-API-Key": key}
    if claimed_name:
        headers["X-Analyst-ID"] = claimed_name
    response = client.post("/api/v1/cases", headers=headers, json=CASE_BODY)
    assert response.status_code == 200, response.text[:150]
    return response.json()["case_id"]


def _actors(client, case_id, key):
    response = client.get(
        f"/api/v1/cases/{case_id}/timeline", headers={"X-API-Key": key}
    )
    return [event["analyst_id"] for event in response.json()["events"]]


def test_a_claimed_name_never_reaches_the_audit_trail():
    client = TestClient(app)
    case_id = _open_case(client, KEY_ONE, claimed_name="mallory")

    actors = _actors(client, case_id, KEY_ONE)

    assert "mallory" not in actors, (
        f"the caller named itself in the audit trail: {actors}. The actor must "
        "come from the credential, not from a request header."
    )


def test_a_mutation_is_attributed_to_the_key_that_made_it():
    client = TestClient(app)
    case_id = _open_case(client, KEY_ONE)
    client.patch(
        f"/api/v1/cases/{case_id}",
        headers={"X-API-Key": KEY_TWO, "X-Analyst-ID": "someone.else"},
        json={"status": "CLOSED"},
    )

    actors = _actors(client, case_id, KEY_ONE)

    assert actors[0] == analyst_id_for_key(KEY_ONE)
    assert actors[-1] == MAPPED_NAME, (
        f"the second action was recorded as {actors[-1]!r} rather than the "
        f"identity mapped to the key that made it"
    )
    assert "someone.else" not in actors


def test_two_actions_from_one_key_share_one_identity():
    client = TestClient(app)
    case_id = _open_case(client, KEY_ONE, claimed_name="first.name")
    client.patch(
        f"/api/v1/cases/{case_id}",
        headers={"X-API-Key": KEY_ONE, "X-Analyst-ID": "second.name"},
        json={"status": "CLOSED"},
    )

    actors = _actors(client, case_id, KEY_ONE)

    assert len(set(actors)) == 1, (
        f"one credential produced several identities in the trail: {actors}"
    )


def test_a_configured_key_is_recorded_under_its_configured_name():
    assert analyst_id_for_key(KEY_TWO) == MAPPED_NAME


def test_an_unmapped_key_gets_a_stable_identifier_that_is_not_the_key():
    identity = analyst_id_for_key(KEY_ONE)

    assert identity == analyst_id_for_key(KEY_ONE), "the identity is not stable"
    assert identity.startswith("api_")
    assert KEY_ONE not in identity, "the raw credential leaked into the trail"
    assert identity != analyst_id_for_key(KEY_TWO)


def test_a_missing_credential_is_not_attributed_to_a_name():
    assert analyst_id_for_key(None) == UNIDENTIFIED_ACTOR
    assert analyst_id_for_key("") == UNIDENTIFIED_ACTOR


def test_the_routes_no_longer_read_an_actor_header():
    """The header is the vulnerability, so its absence is the fix."""
    import io

    source = io.open("src/api/cases_routes.py", encoding="utf-8").read()

    assert "X-Analyst-ID" not in source, (
        "a case route still reads the actor from a request header"
    )
