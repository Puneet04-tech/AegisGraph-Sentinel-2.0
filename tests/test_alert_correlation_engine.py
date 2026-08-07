"""Unit tests for the alert correlation engine.

Covers ``src.alert_correlation.correlation_engine.AlertCorrelationEngine``:
ingestion, deduplication, correlation grouping, suppression rules,
prioritization, incident linking, and dashboard statistics.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from src.alert_correlation.correlation_engine import AlertCorrelationEngine
from src.alert_correlation.models import Alert, AlertSeverity, AlertStatus


@pytest.fixture
def engine() -> AlertCorrelationEngine:
    return AlertCorrelationEngine()


# ---------------------------------------------------------------------------
# Alert ingestion
# ---------------------------------------------------------------------------


class TestIngestion:
    def test_ingest_alert_parses_severity(self, engine):
        alert = engine.ingest_alert(
            "Suspicious login", "Brute force detected", "HIGH", "auth-service"
        )

        assert alert.severity == AlertSeverity.HIGH
        assert alert.status == AlertStatus.NEW
        assert alert.tags == []
        assert alert.indicators == []
        assert alert in engine.alerts.values()

    def test_ingest_alert_preserves_tags_and_indicators(self, engine):
        alert = engine.ingest_alert(
            "Alert", "desc", "LOW", "src", tags=["a"], indicators=["ioc-1"]
        )

        assert alert.tags == ["a"]
        assert alert.indicators == ["ioc-1"]

    def test_get_alert_unknown_returns_none(self, engine):
        assert engine.get_alert("missing") is None

    def test_get_all_alerts_returns_all(self, engine):
        engine.ingest_alert("A", "d", "LOW", "s1")
        engine.ingest_alert("B", "d", "MEDIUM", "s2")

        assert len(engine.get_all_alerts()) == 2


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_deduplicate_alert_marks_suppressed(self, engine):
        dup = engine.ingest_alert("Same title", "d", "LOW", "s")
        original = engine.ingest_alert("Same title", "d", "LOW", "s")

        assert engine.deduplicate_alert(dup.alert_id, original.alert_id) is True
        assert dup.deduplicated is True
        assert dup.deduplicated_by == original.alert_id
        assert dup.status == AlertStatus.SUPPRESSED

    def test_deduplicate_unknown_ids_fails(self, engine):
        alert = engine.ingest_alert("A", "d", "LOW", "s")
        assert engine.deduplicate_alert(alert.alert_id, "missing") is False
        assert engine.deduplicate_alert("missing", alert.alert_id) is False

    def test_similarity_exact_match(self, engine):
        assert engine._calculate_similarity("Login Failed", "login failed") == 1.0

    def test_similarity_substring_match(self, engine):
        assert engine._calculate_similarity("login", "repeated login failed") == 0.8

    def test_similarity_no_match(self, engine):
        assert engine._calculate_similarity("login", "transaction") == 0.0

    def test_find_duplicates_by_title(self, engine):
        engine.ingest_alert("Suspicious transfer", "d", "MEDIUM", "s1")
        duplicate = engine.ingest_alert("Suspicious transfer", "d", "LOW", "s2")

        alert = list(engine.alerts.values())[0]
        found = engine.find_duplicates(alert)

        assert duplicate.alert_id in [a.alert_id for a in found]

    def test_find_duplicates_by_indicator_overlap(self, engine):
        alert_a = engine.ingest_alert("Title A", "d", "LOW", "s1")
        alert_b = engine.ingest_alert("Title B", "d", "LOW", "s2", indicators=["ioc-1"])
        alert_a.indicators = ["ioc-1"]

        found = engine.find_duplicates(alert_a)

        assert alert_b.alert_id in [a.alert_id for a in found]

    def test_find_duplicates_respects_threshold(self, engine):
        alert_a = engine.ingest_alert("suspicious login", "d", "LOW", "s1")
        alert_b = engine.ingest_alert("repeated suspicious login failed", "d", "LOW", "s2")

        # 0.8 substring similarity is below a 0.9 threshold...
        found = engine.find_duplicates(alert_a, threshold=0.9)
        assert found == []

        # ...but matches at the 0.8 threshold.
        found = engine.find_duplicates(alert_a, threshold=0.8)
        assert alert_b.alert_id in [a.alert_id for a in found]

    def test_find_duplicates_excludes_self_and_already_deduplicated(self, engine):
        alert = engine.ingest_alert("Suspicious transfer", "d", "LOW", "s1")
        dup = engine.ingest_alert("Suspicious transfer", "d", "LOW", "s2")
        dup.deduplicated = True

        assert engine.find_duplicates(alert) == []

    def test_find_duplicates_does_not_append_same_alert_twice(self, engine):
        alert = engine.ingest_alert("Suspicious transfer", "d", "LOW", "s1")
        other = engine.ingest_alert(
            "Suspicious transfer", "d", "LOW", "s2", indicators=["ioc-1"]
        )
        alert.indicators = ["ioc-1"]

        # Matches on both title similarity and indicator overlap.
        found = engine.find_duplicates(alert)

        assert [a.alert_id for a in found].count(other.alert_id) == 1


# ---------------------------------------------------------------------------
# Correlation groups
# ---------------------------------------------------------------------------


class TestCorrelation:
    def test_correlate_alerts_requires_two_alerts(self, engine):
        alert = engine.ingest_alert("A", "d", "LOW", "s")

        assert engine.correlate_alerts([alert.alert_id]) is None
        assert engine.correlate_alerts([]) is None

    def test_correlate_alerts_selects_highest_severity_primary(self, engine):
        low = engine.ingest_alert("A", "d", "LOW", "s")
        critical = engine.ingest_alert("B", "d", "CRITICAL", "s")

        group = engine.correlate_alerts([low.alert_id, critical.alert_id])

        assert group is not None
        assert group.primary_alert_id == critical.alert_id
        assert group.group_id in engine.groups

    def test_correlation_score_shared_source_and_indicators(self, engine):
        alert_a = engine.ingest_alert(
            "A", "d", "MEDIUM", "shared-src", indicators=["ioc-1"]
        )
        alert_b = engine.ingest_alert(
            "B", "d", "LOW", "shared-src", indicators=["ioc-1"]
        )
        # Separate timestamps by >1 hour so temporal proximity does not apply.
        alert_b.created_at = alert_a.created_at + timedelta(hours=2)

        score = engine._calculate_correlation_score([alert_a, alert_b])

        assert score == pytest.approx(0.9)  # 0.5 base + 0.2 source + 0.2 indicators

    def test_correlation_score_temporal_proximity(self, engine):
        alert_a = engine.ingest_alert("A", "d", "LOW", "s1")
        alert_b = engine.ingest_alert("B", "d", "LOW", "s2")
        alert_b.created_at = alert_a.created_at + timedelta(seconds=300)

        score = engine._calculate_correlation_score([alert_a, alert_b])

        assert score == pytest.approx(0.6)  # 0.5 base + 0.1 proximity

    def test_correlation_score_single_alert_is_zero(self, engine):
        alert = engine.ingest_alert("A", "d", "LOW", "s")
        assert engine._calculate_correlation_score([alert]) == 0.0


# ---------------------------------------------------------------------------
# Prioritization
# ---------------------------------------------------------------------------


class TestPrioritization:
    def test_prioritize_alerts_sorts_by_severity(self, engine):
        low = engine.ingest_alert("Low", "d", "LOW", "s")
        critical = engine.ingest_alert("Critical", "d", "CRITICAL", "s")

        ordered = engine.prioritize_alerts()

        assert ordered[0].alert_id == critical.alert_id
        assert ordered[1].alert_id == low.alert_id

    def test_prioritize_alerts_excludes_deduplicated(self, engine):
        dup = engine.ingest_alert("A", "d", "CRITICAL", "s")
        dup.deduplicated = True
        engine.ingest_alert("B", "d", "LOW", "s")

        assert all(a.alert_id != dup.alert_id for a in engine.prioritize_alerts())


# ---------------------------------------------------------------------------
# Suppression rules
# ---------------------------------------------------------------------------


class TestSuppression:
    def test_create_suppression_rule_stores(self, engine):
        rule = engine.create_suppression_rule("Block src", "desc", {"source": "10.0.0.1"})

        assert rule.rule_id in engine.suppression_rules
        assert engine.suppression_rules[rule.rule_id].name == "Block src"

    def test_should_suppress_matches_source(self, engine):
        engine.create_suppression_rule("Rule", "d", {"source": "10.0.0.1"})
        alert = engine.ingest_alert("A", "d", "LOW", "10.0.0.1")
        other = engine.ingest_alert("B", "d", "LOW", "10.0.0.2")

        assert engine.should_suppress(alert) is True
        assert engine.should_suppress(other) is False

    def test_should_suppress_matches_severity_and_tag(self, engine):
        engine.create_suppression_rule(
            "Rule", "d", {"severity": "LOW", "tag": "noise"}
        )
        alert = engine.ingest_alert("A", "d", "LOW", "s", tags=["noise"])
        other = engine.ingest_alert("B", "d", "LOW", "s", tags=["important"])

        assert engine.should_suppress(alert) is True
        assert engine.should_suppress(other) is False

    def test_disabled_rule_is_skipped(self, engine):
        rule = engine.create_suppression_rule("Rule", "d", {"source": "10.0.0.1"})
        rule.enabled = False
        alert = engine.ingest_alert("A", "d", "LOW", "10.0.0.1")

        assert engine.should_suppress(alert) is False

    def test_empty_conditions_never_match(self, engine):
        alert = engine.ingest_alert("A", "d", "LOW", "s")
        assert engine._matches_conditions(alert, {}) is False
        assert engine._matches_conditions(alert, None) is False

    def test_unknown_condition_key_fails_match(self, engine):
        alert = engine.ingest_alert("A", "d", "LOW", "s")
        assert engine._matches_conditions(alert, {"unknown": "x"}) is False


# ---------------------------------------------------------------------------
# Incident linking and dashboard
# ---------------------------------------------------------------------------


class TestIncidentAndDashboard:
    def test_link_to_incident(self, engine):
        alert = engine.ingest_alert("A", "d", "LOW", "s")

        assert engine.link_to_incident(alert.alert_id, "inc-1") is True
        assert "inc-1" in alert.linked_incidents
        assert engine.link_to_incident("missing", "inc-1") is False

    def test_get_dashboard_counts(self, engine):
        engine.ingest_alert("A", "d", "LOW", "s1")
        engine.ingest_alert("B", "d", "CRITICAL", "s1")
        engine.ingest_alert("C", "d", "HIGH", "s2")

        dashboard = engine.get_dashboard()

        assert dashboard["total_alerts"] == 3
        assert dashboard["alerts_by_severity"]["LOW"] == 1
        assert dashboard["alerts_by_severity"]["CRITICAL"] == 1
        assert dashboard["alerts_by_source"]["s1"] == 2
        assert dashboard["alerts_by_source"]["s2"] == 1
        assert dashboard["alerts_by_status"]["NEW"] == 3
        assert dashboard["deduplicated_count"] == 0
