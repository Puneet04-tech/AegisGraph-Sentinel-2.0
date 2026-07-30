"""Amount bands must apply to every transaction in degraded scoring mode.

The override that raises a score for high value transactions used to be gated on
the heuristic score already being at or below fallback_trigger_score. The
heuristic exceeds that ceiling for many large amounts, so exactly the
transactions the BLOCK bands exist to catch skipped the override and were
approved on the raw score.
"""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from src.api.main import app, _FALLBACK_SCORING, _is_degraded_scoring_mode

ANALYST_KEY = "fallback-band-test-key"
HEADERS = {"X-API-Key": ANALYST_KEY}

SOURCE = "ACC5550001111"
TARGET = "ACC5550002222"


@pytest.fixture(autouse=True)
def _analyst_auth(monkeypatch):
    monkeypatch.setenv(
        "AEGIS_ROLE_ANALYST", hashlib.sha256(ANALYST_KEY.encode()).hexdigest()
    )
    from src.api.security import _invalidate_auth_cache

    _invalidate_auth_cache()
    _clear_rate_limit_state()
    yield
    _invalidate_auth_cache()


def _clear_rate_limit_state():
    from src.api.main import limiter
    from src.api.validators import reset_rate_limiter

    reset_rate_limiter()
    for attribute in ("storage", "_storage"):
        storage = getattr(limiter, attribute, None)
        if storage is None:
            continue
        inner = getattr(storage, "storage", None)
        if inner is not None:
            inner.clear()
        elif hasattr(storage, "clear"):
            storage.clear()


def _recent_timestamp():
    moment = datetime.now(timezone.utc) - timedelta(minutes=5)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _score(amount, transaction_id):
    payload = {
        "transaction_id": transaction_id,
        "source_account": SOURCE,
        "target_account": TARGET,
        "amount": amount,
        "currency": "INR",
        "mode": "UPI",
        "timestamp": _recent_timestamp(),
    }
    response = TestClient(app).post(
        "/api/v1/fraud/check", headers=HEADERS, json=payload
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["risk_score"], body["decision"]


def _band_floor(amount):
    """Return the score the configured bands require for this amount."""
    cfg = _FALLBACK_SCORING
    if amount > cfg.get("block_above", 200000):
        return cfg.get("block_score", 0.85)
    if amount > cfg.get("block_medium_above", 100000):
        return cfg.get("block_medium_score", 0.72)
    if amount > cfg.get("review_above", 50000):
        return cfg.get("review_score", 0.48)
    if amount > cfg.get("allow_above", 10000):
        return cfg.get("allow_score", 0.35)
    return 0.0


AMOUNTS = [15_000.0, 60_000.0, 150_000.0, 199_999.0, 200_001.0, 300_000.0, 5_000_000.0]


@pytest.mark.skipif(
    not _is_degraded_scoring_mode(),
    reason="amount bands only apply when the model is unavailable",
)
@pytest.mark.parametrize("amount", AMOUNTS)
def test_score_is_never_below_its_configured_band(amount):
    score, _ = _score(amount, f"BAND-{int(amount)}")

    assert score >= _band_floor(amount), (
        f"an amount of {amount:,.0f} scored {score}, below the {_band_floor(amount)} "
        "its configured band requires, so the amount override did not apply"
    )


@pytest.mark.skipif(
    not _is_degraded_scoring_mode(),
    reason="amount bands only apply when the model is unavailable",
)
def test_a_very_large_amount_is_not_approved():
    """The case that motivated this: 5,000,000 was approved while 199,999 blocked."""
    score, decision = _score(5_000_000.0, "BAND-HUGE")

    assert decision != "approve", (
        f"a 5,000,000 transaction was {decision} with score {score}"
    )


@pytest.mark.skipif(
    not _is_degraded_scoring_mode(),
    reason="amount bands only apply when the model is unavailable",
)
def test_score_does_not_decrease_as_amount_increases():
    scores = [_score(a, f"MONO-{int(a)}")[0] for a in AMOUNTS]

    drops = [
        (AMOUNTS[i], scores[i - 1], scores[i])
        for i in range(1, len(scores))
        if scores[i] < scores[i - 1]
    ]

    assert not drops, (
        f"risk score fell as the amount rose, at {drops}. A larger transaction "
        "must not be scored as safer than a smaller one."
    )
