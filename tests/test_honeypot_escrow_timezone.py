"""Escrow release timing must be anchored to UTC, not to the host's zone.

`activate_honeypot` stamped `activation_time` with a naive `datetime.now()` and
derived `auto_release_time` from it, then `check_auto_release` compared against
another naive `datetime.now()`. Escrowed funds are held until that deadline, so
the release instant depended on whichever local zone the process happened to run
in and shifted by an hour across a DST transition. Daily arrest and recovery
counters reset on the host's local calendar date for the same reason.

Mixing a persisted naive datetime with an aware one raises `TypeError` on
comparison, which inside `check_auto_release` would leave funds held
indefinitely.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.features.honeypot_escrow import (
    HoneypotEscrowManager,
    _ensure_aware,
    _utcnow,
)


def naive_utc() -> datetime:
    """A naive UTC datetime, as records persisted before this change carry."""
    return _utcnow().replace(tzinfo=None)


def manager(**kwargs) -> HoneypotEscrowManager:
    return HoneypotEscrowManager(**kwargs)


def activate(mgr, amount=50000.0, account="MULE1"):
    return mgr.activate_honeypot(
        transaction_id="TXN1",
        source_account="VICTIM1",
        target_account=account,
        amount=amount,
        currency="INR",
        risk_score=0.95,
        fraud_indicators=["known_mule_account"],
    )


class TestUtcHelpers:
    def test_utcnow_is_timezone_aware(self):
        assert _utcnow().tzinfo is not None

    def test_utcnow_is_utc(self):
        assert _utcnow().utcoffset() == timedelta(0)

    def test_ensure_aware_treats_naive_as_utc(self):
        naive = datetime(2026, 1, 1, 12, 0, 0)
        assert _ensure_aware(naive) == datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_ensure_aware_preserves_an_aware_instant(self):
        offset = timezone(timedelta(hours=5, minutes=30))
        aware = datetime(2026, 1, 1, 17, 30, 0, tzinfo=offset)
        assert _ensure_aware(aware) == datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_ensure_aware_is_idempotent(self):
        value = _utcnow()
        assert _ensure_aware(_ensure_aware(value)) == _ensure_aware(value)


class TestActivationTimestamps:
    def test_activation_time_is_aware(self):
        honeypot = activate(manager())
        assert honeypot.activation_time.tzinfo is not None

    def test_auto_release_time_is_aware(self):
        honeypot = activate(manager())
        assert honeypot.auto_release_time.tzinfo is not None

    def test_release_deadline_is_the_configured_offset(self):
        honeypot = activate(manager(auto_release_hours=2.0))
        delta = honeypot.auto_release_time - honeypot.activation_time
        assert delta == timedelta(hours=2)

    def test_deadline_is_an_absolute_instant_not_a_wall_clock_time(self):
        """The same configuration must yield the same absolute deadline
        regardless of the host's zone."""
        before = _utcnow()
        honeypot = activate(manager(auto_release_hours=1.0))
        after = _utcnow()
        assert before + timedelta(hours=1) <= honeypot.auto_release_time
        assert honeypot.auto_release_time <= after + timedelta(hours=1)


class TestAutoRelease:
    def test_a_honeypot_past_its_deadline_is_released(self):
        mgr = manager(auto_release_hours=2.0)
        honeypot = activate(mgr)
        honeypot.auto_release_time = _utcnow() - timedelta(seconds=1)

        mgr.check_auto_release()

        assert honeypot.honeypot_id not in mgr.active_honeypots

    def test_a_honeypot_before_its_deadline_is_held(self):
        mgr = manager(auto_release_hours=2.0)
        honeypot = activate(mgr)

        mgr.check_auto_release()

        assert honeypot.honeypot_id in mgr.active_honeypots

    def test_a_naive_persisted_deadline_does_not_wedge_the_release_check(self):
        """A record written before this change carries a naive deadline.
        Comparing it against an aware now() raises TypeError, which would leave
        the victim's funds held indefinitely."""
        mgr = manager(auto_release_hours=2.0)
        honeypot = activate(mgr)
        honeypot.auto_release_time = naive_utc() - timedelta(hours=1)

        mgr.check_auto_release()

        assert honeypot.honeypot_id not in mgr.active_honeypots

    def test_a_naive_future_deadline_is_still_respected(self):
        mgr = manager(auto_release_hours=2.0)
        honeypot = activate(mgr)
        honeypot.auto_release_time = naive_utc() + timedelta(hours=1)

        mgr.check_auto_release()

        assert honeypot.honeypot_id in mgr.active_honeypots

    def test_an_offset_aware_deadline_is_compared_by_instant(self):
        """A deadline expressed in IST must release at the same instant as the
        equivalent UTC deadline, not five and a half hours out."""
        mgr = manager(auto_release_hours=2.0)
        honeypot = activate(mgr)
        ist = timezone(timedelta(hours=5, minutes=30))
        honeypot.auto_release_time = (_utcnow() - timedelta(minutes=1)).astimezone(ist)

        mgr.check_auto_release()

        assert honeypot.honeypot_id not in mgr.active_honeypots


class TestTimeRemaining:
    def test_time_remaining_is_computed_against_an_aware_now(self):
        mgr = manager(auto_release_hours=2.0)
        activate(mgr)

        remaining = mgr.get_active_honeypots()[0]['time_remaining_seconds']

        assert 0 < remaining <= 2 * 3600

    def test_time_remaining_survives_a_naive_persisted_deadline(self):
        mgr = manager(auto_release_hours=2.0)
        honeypot = activate(mgr)
        honeypot.auto_release_time = naive_utc() + timedelta(hours=1)

        remaining = mgr.get_active_honeypots()[0]['time_remaining_seconds']

        assert remaining > 0

    def test_an_elapsed_deadline_reports_zero_not_a_negative(self):
        mgr = manager(auto_release_hours=2.0)
        honeypot = activate(mgr)
        honeypot.auto_release_time = _utcnow() - timedelta(hours=5)

        assert mgr.get_active_honeypots()[0]['time_remaining_seconds'] == 0


class TestDailyCounters:
    def test_daily_date_is_the_utc_date(self):
        assert manager().daily_stats['date'] == _utcnow().date()

    def test_counters_reset_when_the_utc_date_rolls_over(self):
        mgr = manager()
        mgr.daily_stats['arrests'] = 5
        mgr.daily_stats['recovered'] = 100000.0
        mgr.daily_stats['date'] = _utcnow().date() - timedelta(days=1)

        stats = mgr.get_daily_stats()

        assert stats['arrests_today'] == 0
        assert stats['recovered_today'] == 0.0

    def test_counters_persist_within_the_same_utc_day(self):
        mgr = manager()
        mgr.daily_stats['arrests'] = 3
        mgr.daily_stats['recovered'] = 250.0

        stats = mgr.get_daily_stats()

        assert stats['arrests_today'] == 3
        assert stats['recovered_today'] == 250.0


class TestAlertTimestamps:
    def test_police_alert_timestamp_is_aware(self):
        mgr = manager()
        honeypot = activate(mgr)

        mgr.record_withdrawal_attempt(
            account=honeypot.target_account,
            withdrawal_type="ATM",
            amount=10000.0,
            location={"lat": 19.0, "lon": 72.8},
        )

        alert = mgr.active_honeypots[honeypot.honeypot_id].alerts_sent[0]
        assert datetime.fromisoformat(alert['timestamp']).tzinfo is not None

    def test_withdrawal_attempt_timestamp_is_aware(self):
        mgr = manager()
        honeypot = activate(mgr)

        mgr.record_withdrawal_attempt(
            account=honeypot.target_account,
            withdrawal_type="UPI",
            amount=5000.0,
            location={},
        )

        attempt = mgr.active_honeypots[honeypot.honeypot_id].withdrawal_attempts[0]
        assert datetime.fromisoformat(attempt['timestamp']).tzinfo is not None


class TestResponseTimeCalculation:
    def test_response_time_spans_aware_timestamps(self):
        mgr = manager()
        honeypot = activate(mgr)
        mgr.record_withdrawal_attempt(
            account=honeypot.target_account,
            withdrawal_type="ATM",
            amount=10000.0,
            location={},
        )

        arrest_time = (_utcnow() + timedelta(minutes=15)).isoformat()
        mgr.record_arrest(honeypot.honeypot_id, {"arrest_time": arrest_time})

        assert mgr.stats['total_arrests'] >= 1

    def test_a_naive_arrest_time_does_not_raise(self):
        """Callers outside this module may still submit naive ISO strings."""
        mgr = manager()
        honeypot = activate(mgr)
        mgr.record_withdrawal_attempt(
            account=honeypot.target_account,
            withdrawal_type="ATM",
            amount=10000.0,
            location={},
        )

        naive_arrest = (naive_utc() + timedelta(minutes=15)).isoformat()
        mgr.record_arrest(honeypot.honeypot_id, {"arrest_time": naive_arrest})

        assert mgr.stats['total_arrests'] >= 1

    def test_an_offset_arrest_time_is_interpreted_by_instant(self):
        mgr = manager()
        honeypot = activate(mgr)
        mgr.record_withdrawal_attempt(
            account=honeypot.target_account,
            withdrawal_type="ATM",
            amount=10000.0,
            location={},
        )

        ist = timezone(timedelta(hours=5, minutes=30))
        arrest_time = (_utcnow() + timedelta(minutes=15)).astimezone(ist).isoformat()
        mgr.record_arrest(honeypot.honeypot_id, {"arrest_time": arrest_time})

        assert mgr.stats['total_arrests'] >= 1
