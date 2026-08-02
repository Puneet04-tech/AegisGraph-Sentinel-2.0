"""An oversized voice payload must be refused as 413, not 422.

The schema estimated the decoded size as `len(base64) * 0.75` and rejected
anything over 350,000. Any payload whose decoded size exceeds that necessarily
has a base64 string longer than 466,667 characters, so the schema always fired
first and the handler's 413 branch could never run.
"""

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

import src.api.main as api_main
from src.api.main import app
from src.api.schemas import VoiceAnalysisRequest
from src.api.security import _invalidate_auth_cache

API_KEY = "voice-size-test-key"

# Decodes to more than the handler's 350,000 byte cap, while staying inside the
# schema's 500,000 character cap on the encoded string.
OVERSIZED_DECODED = base64.b64encode(b"\0" * 360_000).decode()

# Larger than the encoded-string cap, so the schema is what should refuse it.
OVERSIZED_ENCODED = "A" * 500_001


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    digest = hashlib.sha256(API_KEY.encode()).hexdigest()
    for role in ("ANALYST", "ADMIN", "SUPER_ADMIN"):
        monkeypatch.setenv(f"AEGIS_ROLE_{role}", digest)
    _invalidate_auth_cache()
    yield
    _invalidate_auth_cache()


def _post(audio_base64):
    return TestClient(app).post(
        "/api/v1/voice/analyze",
        headers={"X-API-Key": API_KEY},
        json={
            "transaction_id": "TXN_VOICE_SIZE",
            "audio_base64": audio_base64,
            "sample_rate": 16000,
        },
    )


def test_the_encoded_cap_is_large_enough_to_reach_the_decoded_cap():
    """If it were not, the handler's 413 would be unreachable by construction."""
    assert len(OVERSIZED_DECODED) < 500_000, (
        "a payload decoding past the handler's limit cannot be expressed within "
        "the schema's limit, so the 413 branch is dead code"
    )


def test_a_payload_over_the_decoded_limit_is_accepted_by_the_schema():
    """The schema must not pre-empt the handler's exact measurement."""
    request = VoiceAnalysisRequest(
        transaction_id="TXN_VOICE_SIZE",
        audio_base64=OVERSIZED_DECODED,
        sample_rate=16000,
    )

    assert len(base64.b64decode(request.audio_base64)) > 350_000


def test_an_oversized_decoded_payload_is_refused_as_too_large():
    response = _post(OVERSIZED_DECODED)

    assert response.status_code == 413, (
        f"an oversized payload was refused with {response.status_code} rather "
        "than 413. The schema rejected it on an estimate before the handler "
        "could measure the decoded bytes."
    )


def test_an_oversized_encoded_payload_is_still_refused_by_the_schema():
    """Removing the estimate must not remove the bound on the encoded string."""
    response = _post(OVERSIZED_ENCODED)

    assert response.status_code == 422


def test_the_schema_rejects_an_over_long_string_directly():
    with pytest.raises(ValueError):
        VoiceAnalysisRequest(
            transaction_id="TXN_VOICE_SIZE",
            audio_base64=OVERSIZED_ENCODED,
            sample_rate=16000,
        )
