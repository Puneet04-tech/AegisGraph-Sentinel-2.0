"""A step-up challenge must not be satisfied by the party being challenged.

Four of the challenge types decided success from the verify request itself:
three read a boolean out of the caller-supplied ``context``, and the fourth
compared answers against a mapping that was empty, which made its loop vacuous.
Step-up exists to require evidence the caller cannot produce, so any of these
passing defeats the control entirely.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from src.adaptive_auth.service import create_session_sync, get_adaptive_auth_service
from src.api.main import app
from src.api.security import _invalidate_auth_cache
from src.api.validators import reset_rate_limiter

API_KEY = "stepup-contract-test-key"

# (challenge type, body a caller can send to assert its own success)
SELF_ASSERTIONS = [
    ("biometric", {"response": "anything", "context": {"biometric_verified": True}}),
    ("callback", {"response": "anything", "context": {"callback_verified": True}}),
    ("push_notification", {"response": "approved"}),
    ("security_questions", {"response": "anything", "context": {"answers": {}}}),
]


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


def _open_challenge(client, challenge_type, user):
    session = create_session_sync(user_id=user, ip_address="203.0.113.7")
    response = client.post(
        f"/api/v1/adaptive-auth/challenge"
        f"?session_id={session.session_id}&user_id={user}",
        headers={"X-API-Key": API_KEY},
        json={"challenge_type": challenge_type},
    )
    assert response.status_code == 200, (
        f"could not open a {challenge_type} challenge: {response.text[:120]}"
    )
    return response.json()["challenge_id"]


def _verify(client, challenge_id, body):
    return client.post(
        f"/api/v1/adaptive-auth/verify?challenge_id={challenge_id}",
        headers={"X-API-Key": API_KEY},
        json=body,
    )


@pytest.mark.parametrize("challenge_type,body", SELF_ASSERTIONS, ids=[c[0] for c in SELF_ASSERTIONS])
def test_a_caller_cannot_assert_its_own_step_up_success(challenge_type, body):
    client = TestClient(app)
    challenge_id = _open_challenge(client, challenge_type, f"victim-{challenge_type}")

    response = _verify(client, challenge_id, body)

    assert response.status_code == 200
    assert response.json()["success"] is False, (
        f"a {challenge_type} challenge was satisfied by the verify request "
        f"itself, using {body}. Step-up authentication provides no protection "
        "if the party being challenged can declare it passed."
    )


def test_an_out_of_band_attestation_still_satisfies_a_challenge():
    """Closing the bypass must not leave the challenge types unusable."""
    client = TestClient(app)
    challenge_id = _open_challenge(client, "biometric", "genuine-user")
    get_adaptive_auth_service().stepup_service.record_external_verification(
        challenge_id, "biometric"
    )

    response = _verify(client, challenge_id, {"response": "anything"})

    assert response.json()["success"] is True


def test_an_attestation_for_one_challenge_does_not_satisfy_another():
    client = TestClient(app)
    attested = _open_challenge(client, "biometric", "user-one")
    other = _open_challenge(client, "biometric", "user-two")
    get_adaptive_auth_service().stepup_service.record_external_verification(
        attested, "biometric"
    )

    assert _verify(client, other, {"response": "anything"}).json()["success"] is False


def test_an_attestation_for_the_wrong_factor_does_not_satisfy_a_challenge():
    client = TestClient(app)
    challenge_id = _open_challenge(client, "biometric", "user-three")
    get_adaptive_auth_service().stepup_service.record_external_verification(
        challenge_id, "push"
    )

    assert _verify(client, challenge_id, {"response": "anything"}).json()["success"] is False


def test_security_questions_still_verify_against_a_populated_mapping():
    """The empty-mapping fix must not break the case the type exists for."""
    service = get_adaptive_auth_service().stepup_service
    client = TestClient(app)
    challenge_id = _open_challenge(client, "security_questions", "quizzed-user")
    challenge = service.store.get_challenge(challenge_id)
    challenge.metadata["correct_answers"] = {"first_pet": "Rex"}
    service.store.update_challenge(challenge)

    wrong = _verify(client, challenge_id, {"response": "x", "context": {"answers": {"first_pet": "Fido"}}})
    assert wrong.json()["success"] is False

    right = _verify(client, challenge_id, {"response": "x", "context": {"answers": {"first_pet": "rex"}}})
    assert right.json()["success"] is True


def test_an_otp_challenge_still_rejects_a_wrong_code():
    """Control case: the type that was already correct must stay correct."""
    client = TestClient(app)
    challenge_id = _open_challenge(client, "sms_otp", "otp-user")

    response = _verify(client, challenge_id, {"response": "000000"})

    assert response.json()["success"] is False
