"""OTP non-echo tests for the adaptive authentication service.

Regression guard for issue #2864: ``initiate_challenge()`` returned the
generated OTP to the caller in the ``otp_code`` response field ("for demo
purposes"). In production the code is delivered out-of-band (SMS/email) and
must never be echoed to the client; the challenge record keeps it solely so
the subsequent ``verify_challenge()`` call can check it.
"""

import asyncio

from src.adaptive_auth.models import ChallengeType
from src.adaptive_auth.service import get_adaptive_auth_service, reset_service
from src.adaptive_auth.store import (
    get_adaptive_auth_store,
    reset_store,
)
from src.adaptive_auth.audit import reset_audit_service


def _reset():
    reset_audit_service()
    reset_store()
    reset_service()


def _run(coro):
    return asyncio.run(coro)


def test_initiate_challenge_does_not_echo_otp():
    _reset()
    service = get_adaptive_auth_service()
    store = get_adaptive_auth_store()
    session = store.create_session(user_id="user1")

    async def scenario():
        response = await service.initiate_challenge(
            session_id=session.session_id,
            user_id="user1",
            challenge_type=ChallengeType.EMAIL_OTP.value,
        )

        # The challenge still generated an OTP internally (verifiable below)...
        challenge = store.get_challenge(response["challenge_id"])
        assert challenge is not None
        assert challenge.metadata.get("otp_to_send") is not None

        # ...but the initiate response must never leak it.
        assert "otp_code" not in response
        assert challenge.metadata["otp_to_send"] not in list(response.values())

    _run(scenario())


def test_otp_remains_usable_for_verification():
    _reset()
    service = get_adaptive_auth_service()
    store = get_adaptive_auth_store()
    session = store.create_session(user_id="user1")

    async def scenario():
        response = await service.initiate_challenge(
            session_id=session.session_id,
            user_id="user1",
            challenge_type=ChallengeType.SMS_OTP.value,
        )

        challenge = store.get_challenge(response["challenge_id"])
        otp = challenge.metadata.get("otp_to_send")
        assert otp is not None

        result = service.stepup_service.verify_challenge(response["challenge_id"], otp)
        assert result.success is True

    _run(scenario())
