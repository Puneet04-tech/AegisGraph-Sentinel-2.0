"""Unit tests for impossible-travel detection in the adaptive auth risk engine.

These tests pin the behaviour of `RiskEngine.evaluate_impossible_travel`:
impossible travel must only be flagged when the elapsed time between two
actions is too short for the implied movement. Logins from different
countries that are hours or days apart are normal and must score 0.0.
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.adaptive_auth.risk_engine import RiskSignalEvaluator
from src.adaptive_auth.store import get_adaptive_auth_store, reset_store


def _action(hours_ago, country, city):
    """Build a recent action with a timestamp offset by hours_ago."""
    timestamp = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
    return {
        "action": "login",
        "resource": "/api/v1/auth/login",
        "location": {"country": country, "city": city},
        "timestamp": timestamp,
    }


def _session(recent_actions):
    store = get_adaptive_auth_store()
    session = store.create_session(user_id="travel-user")
    session.recent_actions = list(recent_actions)
    return session


def _evaluate(recent_actions):
    reset_store()
    store = get_adaptive_auth_store()
    session = _session(recent_actions)
    profile = store.get_or_create_profile("travel-user")
    return RiskSignalEvaluator(store).evaluate_impossible_travel(session, profile)


def test_no_actions_scores_zero():
    signal = _evaluate([])
    assert signal.value == 0.0
    assert signal.metadata["locations_compared"] == 0
    assert signal.metadata["time_since_last"] is None


def test_single_action_scores_zero():
    signal = _evaluate([_action(1, "USA", "New York")])
    assert signal.value == 0.0
    assert signal.metadata["locations_compared"] == 0


def test_same_location_scores_zero():
    signal = _evaluate([
        _action(10, "USA", "New York"),
        _action(1, "USA", "New York"),
    ])
    assert signal.value == 0.0


def test_same_country_different_cities_within_window_scores_high():
    signal = _evaluate([
        _action(1, "USA", "New York"),
        _action(0, "USA", "Los Angeles"),
    ])
    assert signal.value == 0.3
    assert signal.metadata["locations_compared"] == 2


def test_same_country_different_cities_with_enough_time_scores_zero():
    signal = _evaluate([
        _action(10, "USA", "New York"),
        _action(1, "USA", "Los Angeles"),
    ])
    assert signal.value == 0.0


def test_cross_country_within_window_scores_high():
    signal = _evaluate([
        _action(1, "USA", "New York"),
        _action(0, "Japan", "Tokyo"),
    ])
    assert signal.value == 0.8


def test_cross_country_days_apart_scores_zero():
    signal = _evaluate([
        _action(30 * 24, "USA", "New York"),
        _action(2 * 24, "Japan", "Tokyo"),
    ])
    assert signal.value == 0.0


def test_cross_country_exactly_at_threshold_scores_zero():
    signal = _evaluate([
        _action(12, "USA", "New York"),
        _action(0, "Japan", "Tokyo"),
    ])
    assert signal.value == 0.0


def test_time_since_last_is_recorded():
    signal = _evaluate([
        _action(5, "USA", "New York"),
        _action(1, "USA", "New York"),
    ])
    assert signal.metadata["locations_compared"] == 2
    assert signal.metadata["time_since_last"] == pytest.approx(4.0)


def test_older_latest_timestamp_does_not_flag():
    signal = _evaluate([
        _action(0, "Japan", "Tokyo"),
        _action(1, "USA", "New York"),
    ])
    assert signal.value == 0.0
