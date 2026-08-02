"""
Tests for per-rule cooldown honoring and dedup key pruning in AlertManager.

Regression coverage for:
    - `AlertRule.cooldown_seconds` being silently ignored by
      `AlertManager.evaluate_rules` (always used the manager-wide 300s
      dedup window regardless of the rule's configured cooldown).
    - `_recent_alerts` growing unbounded across long-running instances
      because stale dedup keys were never pruned.
"""

from datetime import timedelta

import pytest

from src.observability.store import ObservabilityStore
from src.observability.alert_manager import AlertManager
from src.observability.models import AlertSeverity, AlertStatus


@pytest.fixture
def manager():
    """Fresh AlertManager with an isolated store."""
    return AlertManager(store=ObservabilityStore())


def _add_rule(manager, name, cooldown_seconds=300, threshold=5.0):
    """Create a simple threshold rule and return it."""
    return manager.create_rule(
        name=name,
        description=f"Alert when errors exceed {threshold}",
        condition={"metric": "errors", "threshold": threshold, "operator": "gt"},
        severity=AlertSeverity.HIGH,
        cooldown_seconds=cooldown_seconds,
    )


def _age_dedup_keys(manager, minutes):
    """Manually rewind all stored dedup timestamps for time-travel tests."""
    for key in list(manager._recent_alerts):
        manager._recent_alerts[key] = manager._recent_alerts[key] - timedelta(minutes=minutes)


class TestPerRuleCooldownHonored:
    """Rule-level cooldown_seconds must drive dedup, not the global 300s."""

    def test_zero_cooldown_fires_on_every_evaluation(self, manager):
        _add_rule(manager, "instant-fire", cooldown_seconds=0)

        first = manager.evaluate_rules({"errors": 10}, "api")
        second = manager.evaluate_rules({"errors": 10}, "api")

        assert len(first) == 1
        assert len(second) == 1

    def test_zero_cooldown_fires_twice_in_a_row(self, manager):
        _add_rule(manager, "instant-fire", cooldown_seconds=0)

        manager.evaluate_rules({"errors": 10}, "api")
        manager.evaluate_rules({"errors": 10}, "api")
        manager.evaluate_rules({"errors": 10}, "api")

        assert len(manager.get_recent_alerts(limit=100)) == 3

    def test_long_cooldown_suppresses_early_retrigger(self, manager):
        _add_rule(manager, "hourly", cooldown_seconds=3600)

        first = manager.evaluate_rules({"errors": 10}, "api")
        _age_dedup_keys(manager, minutes=10)
        second = manager.evaluate_rules({"errors": 10}, "api")

        assert len(first) == 1
        assert len(second) == 0

    def test_long_cooldown_refires_after_window(self, manager):
        _add_rule(manager, "hourly", cooldown_seconds=3600)

        manager.evaluate_rules({"errors": 10}, "api")
        _age_dedup_keys(manager, minutes=10)
        manager.evaluate_rules({"errors": 10}, "api")
        _age_dedup_keys(manager, minutes=55)
        after_window = manager.evaluate_rules({"errors": 10}, "api")

        assert len(after_window) == 1

    def test_default_cooldown_still_dedups(self, manager):
        _add_rule(manager, "default-rule", cooldown_seconds=300)

        first = manager.evaluate_rules({"errors": 10}, "api")
        second = manager.evaluate_rules({"errors": 10}, "api")

        assert len(first) == 1
        assert len(second) == 0

    def test_rule_create_stores_cooldown(self, manager):
        rule = _add_rule(manager, "custom", cooldown_seconds=1234)

        fetched = manager.get_rule(rule.rule_id)
        assert fetched.cooldown_seconds == 1234

    def test_rule_created_without_cooldown_uses_default(self, manager):
        rule = manager.create_rule(
            name="implicit",
            description="desc",
            condition={"metric": "errors", "threshold": 5, "operator": "gt"},
            severity=AlertSeverity.LOW,
        )

        assert rule.cooldown_seconds == 300


class TestMixedCooldownsIndependent:
    """Rules with different cooldowns must not interfere with each other."""

    def test_independent_dedup_across_rules(self, manager):
        _add_rule(manager, "instant-fire", cooldown_seconds=0)
        _add_rule(manager, "slow-rule", cooldown_seconds=3600)

        first = manager.evaluate_rules({"errors": 10}, "api")
        second = manager.evaluate_rules({"errors": 10}, "api")

        assert len(first) == 2
        assert len(second) == 1

    def test_each_rule_tracks_own_window(self, manager):
        _add_rule(manager, "instant-fire", cooldown_seconds=0)
        _add_rule(manager, "slow-rule", cooldown_seconds=3600)

        manager.evaluate_rules({"errors": 10}, "api")
        _age_dedup_keys(manager, minutes=20)

        third = manager.evaluate_rules({"errors": 10}, "api")

        assert len(third) == 1
        assert "instant-fire" in third[0].title

        _age_dedup_keys(manager, minutes=50)

        fourth = manager.evaluate_rules({"errors": 10}, "api")

        assert len(fourth) == 2

    def test_disabled_rule_stops_firing(self, manager):
        rule = _add_rule(manager, "once-rule", cooldown_seconds=0)
        manager.disable_rule(rule.rule_id)

        result = manager.evaluate_rules({"errors": 10}, "api")

        assert result == []

    def test_reenabled_rule_resumes_firing(self, manager):
        rule = _add_rule(manager, "toggle-rule", cooldown_seconds=0)
        manager.disable_rule(rule.rule_id)
        manager.enable_rule(rule.rule_id)

        result = manager.evaluate_rules({"errors": 10}, "api")

        assert len(result) == 1


class TestDirectCreateAlertCooldown:
    """create_alert must accept an explicit per-call cooldown."""

    def test_direct_alert_with_custom_cooldown(self, manager):
        first = manager.create_alert(
            title="api-latency",
            description="high latency",
            severity=AlertSeverity.HIGH,
            component="api",
            cooldown_seconds=0,
        )
        second = manager.create_alert(
            title="api-latency",
            description="high latency",
            severity=AlertSeverity.HIGH,
            component="api",
            cooldown_seconds=0,
        )

        assert first is not None
        assert second is not None

    def test_direct_alert_default_cooldown_dedups(self, manager):
        first = manager.create_alert(
            title="api-latency",
            description="high latency",
            severity=AlertSeverity.HIGH,
            component="api",
        )
        second = manager.create_alert(
            title="api-latency",
            description="high latency",
            severity=AlertSeverity.HIGH,
            component="api",
        )

        assert first is not None
        assert second is None

    def test_direct_alert_with_long_cooldown(self, manager):
        manager.create_alert(
            title="db-down",
            description="database unreachable",
            severity=AlertSeverity.CRITICAL,
            component="database",
            cooldown_seconds=3600,
        )
        _age_dedup_keys(manager, minutes=30)
        retrigger = manager.create_alert(
            title="db-down",
            description="database unreachable",
            severity=AlertSeverity.CRITICAL,
            component="database",
            cooldown_seconds=3600,
        )

        assert retrigger is None

    def test_different_components_dedup_independently(self, manager):
        manager.create_alert(
            title="latency",
            description="high latency",
            severity=AlertSeverity.HIGH,
            component="api",
            cooldown_seconds=3600,
        )
        other = manager.create_alert(
            title="latency",
            description="high latency",
            severity=AlertSeverity.HIGH,
            component="db",
            cooldown_seconds=3600,
        )

        assert other is not None


class TestStaleKeyPruning:
    """_recent_alerts must stay bounded by the largest cooldown window."""

    def test_stale_entry_pruned_on_next_create(self, manager):
        manager.create_alert(
            title="old-alert",
            description="once",
            severity=AlertSeverity.LOW,
            component="api",
            cooldown_seconds=300,
        )
        _age_dedup_keys(manager, minutes=30)

        manager.create_alert(
            title="new-alert",
            description="fresh",
            severity=AlertSeverity.LOW,
            component="api",
            cooldown_seconds=300,
        )

        assert "api:old-alert" not in manager._recent_alerts
        assert "api:new-alert" in manager._recent_alerts

    def test_fresh_entry_not_pruned(self, manager):
        manager.create_alert(
            title="fresh-alert",
            description="recent",
            severity=AlertSeverity.LOW,
            component="api",
            cooldown_seconds=3600,
        )

        manager.create_alert(
            title="another-alert",
            description="recent",
            severity=AlertSeverity.LOW,
            component="api",
            cooldown_seconds=3600,
        )

        assert "api:fresh-alert" in manager._recent_alerts
        assert "api:another-alert" in manager._recent_alerts

    def test_bounded_growth_across_many_fires(self, manager):
        for i in range(50):
            manager.create_alert(
                title=f"alert-{i}",
                description="burst",
                severity=AlertSeverity.LOW,
                component="api",
                cooldown_seconds=300,
            )
            _age_dedup_keys(manager, minutes=10)

        assert len(manager._recent_alerts) <= 50

    def test_long_window_entry_survives_short_window_prune(self, manager):
        manager.create_alert(
            title="long-window",
            description="hourly",
            severity=AlertSeverity.MEDIUM,
            component="api",
            cooldown_seconds=3600,
        )
        _age_dedup_keys(manager, minutes=10)
        manager.create_alert(
            title="short-window",
            description="minutes",
            severity=AlertSeverity.MEDIUM,
            component="api",
            cooldown_seconds=300,
        )

        assert "api:long-window" in manager._recent_alerts

    def test_prune_after_full_long_window(self, manager):
        manager.create_alert(
            title="long-gone",
            description="expired",
            severity=AlertSeverity.MEDIUM,
            component="api",
            cooldown_seconds=3600,
        )
        _age_dedup_keys(manager, minutes=70)
        manager.create_alert(
            title="trigger",
            description="triggers prune",
            severity=AlertSeverity.MEDIUM,
            component="api",
            cooldown_seconds=300,
        )

        assert "api:long-gone" not in manager._recent_alerts


class TestAlertLifecycleWithCooldown:
    """Cooldown behavior must not break alert lifecycle operations."""

    def test_created_alert_is_active(self, manager):
        alert = manager.create_alert(
            title="active-alert",
            description="status check",
            severity=AlertSeverity.HIGH,
            component="api",
            cooldown_seconds=0,
        )

        assert alert.status == AlertStatus.ACTIVE
        assert alert.alert_id is not None

    def test_rule_alert_is_persisted(self, manager):
        _add_rule(manager, "persist-me", cooldown_seconds=0)
        alerts = manager.evaluate_rules({"errors": 10}, "api")

        assert len(alerts) == 1
        assert len(manager.get_recent_alerts(limit=100)) == 1

    def test_acknowledge_after_cooldown_fire(self, manager):
        alert = manager.create_alert(
            title="ack-me",
            description="status check",
            severity=AlertSeverity.MEDIUM,
            component="api",
            cooldown_seconds=0,
        )

        acknowledged = manager.acknowledge_alert(alert.alert_id, "analyst1")

        assert acknowledged.status == AlertStatus.ACKNOWLEDGED

    def test_resolve_after_cooldown_fire(self, manager):
        alert = manager.create_alert(
            title="resolve-me",
            description="status check",
            severity=AlertSeverity.LOW,
            component="api",
            cooldown_seconds=0,
        )

        resolved = manager.resolve_alert(alert.alert_id)

        assert resolved.status == AlertStatus.RESOLVED

    def test_rule_alert_links_rule_id(self, manager):
        rule = _add_rule(manager, "linked-rule", cooldown_seconds=0)
        alerts = manager.evaluate_rules({"errors": 10}, "api")

        assert alerts[0].rule_id == rule.rule_id
