"""Dedicated unit tests for src/threat_hunting/intelligence_connector.py.

``ThreatIntelligenceConnector`` flags known-malicious IPs and domains and
registers CRITICAL indicators in the hunting store.  These tests pin both the
match and no-match paths plus the store side-effects.
"""

import pytest

from src.threat_hunting.intelligence_connector import ThreatIntelligenceConnector
from src.threat_hunting.models import IndicatorType, ThreatSeverity
from src.threat_hunting.store import ThreatHuntingStore


@pytest.fixture
def connector() -> ThreatIntelligenceConnector:
    return ThreatIntelligenceConnector(store=ThreatHuntingStore())


def test_check_known_malicious_ip(connector):
    indicator = connector.check_ip("198.51.100.42")
    assert indicator is not None
    assert indicator.indicator_type == IndicatorType.IP
    assert indicator.severity == ThreatSeverity.CRITICAL
    assert indicator.confidence == 0.95
    assert indicator.attributes["source"] == "abuseipdb_mock"


def test_check_benign_ip_returns_none(connector):
    assert connector.check_ip("8.8.8.8") is None


def test_check_known_malicious_domain(connector):
    indicator = connector.check_domain("attacker.com")
    assert indicator is not None
    assert indicator.indicator_type == IndicatorType.DOMAIN
    assert indicator.severity == ThreatSeverity.CRITICAL
    assert indicator.confidence == 0.9


def test_check_benign_domain_returns_none(connector):
    assert connector.check_domain("example.com") is None


def test_match_persists_indicator_to_store(connector):
    connector.check_ip("185.220.101.5")
    stored = connector.store.list_indicators()
    assert len(stored) == 1
    assert stored[0].value == "185.220.101.5"


def test_no_match_does_not_touch_store(connector):
    connector.check_ip("1.2.3.4")
    connector.check_domain("safe.example.com")
    assert connector.store.list_indicators() == []
