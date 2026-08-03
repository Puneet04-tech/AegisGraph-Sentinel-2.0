"""Dedicated unit tests for src/threat_hunting/campaign_detector.py.

``CampaignDetector.detect_campaigns`` clusters stored threat indicators by
their ``value`` and emits a ``ThreatCampaign`` when >= 3 indicators share
a value.  These tests pin the clustering threshold, the entity-fallback
logic, the existing-campaign merge path and the store side effects.
"""

from __future__ import annotations

import pytest

from src.threat_hunting.campaign_detector import CampaignDetector
from src.threat_hunting.models import (
    CampaignStatus,
    IndicatorType,
    ThreatCampaign,
    ThreatIndicator,
    ThreatSeverity,
)
from src.threat_hunting.store import ThreatHuntingStore


def _indicator(value: str, itype: IndicatorType = IndicatorType.IP) -> ThreatIndicator:
    return ThreatIndicator(
        indicator_type=itype,
        value=value,
        description=f"indicator for {value}",
    )


@pytest.fixture
def store() -> ThreatHuntingStore:
    return ThreatHuntingStore()


@pytest.fixture
def detector(store: ThreatHuntingStore) -> CampaignDetector:
    return CampaignDetector(store=store)


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------


def test_no_indicators_yields_no_campaigns(detector):
    assert detector.detect_campaigns() == []
    assert detector.store.list_campaigns() == []


def test_two_indicators_below_threshold(detector, store):
    for _ in range(2):
        store.register_indicator(_indicator("100.0.0.1"))
    assert detector.detect_campaigns() == []
    assert store.list_campaigns() == []


def test_three_indicators_creates_campaign(detector, store):
    ids = []
    for _ in range(3):
        ind = _indicator("100.0.0.1")
        store.register_indicator(ind)
        ids.append(ind.indicator_id)

    campaigns = detector.detect_campaigns()
    assert len(campaigns) == 1
    c = campaigns[0]
    assert c.name == "Coordinated Activity on 100.0.0.1"
    assert c.status == CampaignStatus.ACTIVE
    assert c.severity == ThreatSeverity.HIGH
    assert c.confidence == pytest.approx(0.8)
    # IP indicators are not BEHAVIOR/FINGERPRINT -> entity fallback to [val]
    assert c.associated_entities == ["100.0.0.1"]
    assert set(c.associated_indicators) == set(ids)


# ---------------------------------------------------------------------------
# Entity derivation branches
# ---------------------------------------------------------------------------


def test_behavior_indicators_populate_entities_from_filter(detector, store):
    for _ in range(3):
        store.register_indicator(_indicator("acct-A", IndicatorType.BEHAVIOR))
    c = detector.detect_campaigns()[0]
    assert c.associated_entities == ["acct-A"]


def test_fingerprint_indicators_populate_entities(detector, store):
    for _ in range(3):
        store.register_indicator(_indicator("acct-B", IndicatorType.FINGERPRINT))
    c = detector.detect_campaigns()[0]
    assert c.associated_entities == ["acct-B"]


def test_mixed_indicator_types_group_by_value(detector, store):
    for _ in range(3):
        store.register_indicator(_indicator("shared-val"))  # default BEHAVIOR
    c = detector.detect_campaigns()[0]
    assert set(c.associated_indicators) == set(i.indicator_id for i in store.list_indicators())


# ---------------------------------------------------------------------------
# Description / store side effects
# ---------------------------------------------------------------------------


def test_description_reports_indicator_count(detector, store):
    for _ in range(5):
        store.register_indicator(_indicator("100.0.0.1"))
    c = detector.detect_campaigns()[0]
    assert "5 threat indicators" in c.description


def test_campaign_is_stored(detector, store):
    for _ in range(3):
        store.register_indicator(_indicator("100.0.0.1"))
    assert store.get_stats()["stats_counters"]["campaigns_detected"] == 0
    detector.detect_campaigns()
    assert store.get_stats()["stats_counters"]["campaigns_detected"] == 1
    assert len(store.list_campaigns()) == 1


def test_multiple_distinct_values_create_separate_campaigns(detector, store):
    for _ in range(3):
        store.register_indicator(_indicator("100.0.0.1"))
    for _ in range(3):
        store.register_indicator(_indicator("200.0.0.1"))
    campaigns = detector.detect_campaigns()
    assert {c.name for c in campaigns} == {
        "Coordinated Activity on 100.0.0.1",
        "Coordinated Activity on 200.0.0.1",
    }
    assert len(campaigns) == 2


# ---------------------------------------------------------------------------
# Existing-campaign merge path
# ---------------------------------------------------------------------------


def test_existing_campaign_is_updated_not_duplicated(detector, store):
    existing = ThreatCampaign(
        campaign_id="pre-existing-id",
        name="Coordinated Activity on 100.0.0.1",
        associated_entities=[],
        associated_indicators=[],
    )
    store.set_campaign(existing)

    for _ in range(3):
        store.register_indicator(_indicator("100.0.0.1", IndicatorType.BEHAVIOR))

    campaigns = detector.detect_campaigns()
    assert len(campaigns) == 1
    # Same campaign object, not a fresh one.
    assert campaigns[0].campaign_id == "pre-existing-id"
    registered_ids = {i.indicator_id for i in store.list_indicators()}
    assert set(campaigns[0].associated_indicators) == registered_ids
    assert campaigns[0].associated_entities == ["100.0.0.1"]
