"""Threat intelligence enrichment must come from the CTI store.

`enrich_ioc` returned `random.randint(0, 10)` threat associations, a
`random.choice` prevalence band, and — worst of all — a `random.choice` source
country. Attributing an indicator to a randomly selected country is worse than
returning nothing: it is a specific, actionable-looking claim about the origin
of an attack with no basis whatsoever.
"""

from __future__ import annotations

import pytest

from src.cyber_threat_intel.models import (
    IOC,
    Campaign,
    IOCType,
    ThreatActor,
    ThreatCategory,
    ThreatLevel,
)
from src.cyber_threat_intel.store import CTIStore
from src.multi_agent_soc.store import SOCStore
from src.multi_agent_soc.threat_intelligence_agent import ThreatIntelligenceAgent


@pytest.fixture
def cti() -> CTIStore:
    return CTIStore()


@pytest.fixture
def agent(cti) -> ThreatIntelligenceAgent:
    return ThreatIntelligenceAgent(store=SOCStore(), cti_store=cti)


def seed_ioc(cti, value="203.0.113.5", confidence=0.8, country=None, campaigns=0):
    ioc = IOC(
        ioc_id="ioc-1",
        indicator_type=IOCType.IP,
        value=value,
        threat_level=ThreatLevel.HIGH,
        confidence=confidence,
        metadata={"country": country} if country else {},
    )
    cti.add_ioc(ioc)
    for i in range(campaigns):
        cti.add_campaign(
            Campaign(
                campaign_id=f"camp-{i}",
                name=f"Campaign {i}",
                description="",
                actors=[f"actor-{i}"],
                iocs=["ioc-1"],
            )
        )
    return ioc


class TestUnknownIndicators:
    """The core fix: no data means no claim."""

    def test_an_unknown_indicator_is_reported_as_unknown(self, agent):
        result = agent.enrich_ioc({"type": "ip_address", "value": "198.51.100.1"})

        assert result["known"] is False
        assert result["threat_associations"] == 0
        assert result["historical_prevalence"] == "unknown"
        assert result["confidence_score"] == 0.0

    def test_no_country_is_ever_attributed_without_a_record(self, agent):
        result = agent.enrich_ioc({"type": "ip_address", "value": "198.51.100.1"})
        assert "geolocation" not in result

    def test_enrichment_is_deterministic(self, agent):
        payload = {"type": "ip_address", "value": "198.51.100.1"}
        results = {agent.enrich_ioc(payload)["threat_associations"] for _ in range(50)}
        assert results == {0}

    def test_the_module_no_longer_imports_random(self):
        import src.multi_agent_soc.threat_intelligence_agent as module

        assert not hasattr(module, "random")


class TestKnownIndicators:
    def test_confidence_comes_from_the_stored_record(self, agent, cti):
        seed_ioc(cti, confidence=0.42)
        result = agent.enrich_ioc({"type": "ip_address", "value": "203.0.113.5"})

        assert result["known"] is True
        assert result["confidence_score"] == pytest.approx(0.42)

    def test_associations_count_real_campaigns_and_actors(self, agent, cti):
        seed_ioc(cti, campaigns=2)
        result = agent.enrich_ioc({"type": "ip_address", "value": "203.0.113.5"})

        # Two campaigns plus their two distinct actors.
        assert result["threat_associations"] == 4

    def test_prevalence_follows_the_observed_campaign_count(self, agent, cti):
        seed_ioc(cti, campaigns=1)
        assert agent.enrich_ioc(
            {"type": "ip_address", "value": "203.0.113.5"}
        )["historical_prevalence"] == "rare"

    def test_a_country_is_reported_only_when_stored(self, agent, cti):
        seed_ioc(cti, country="NL")
        result = agent.enrich_ioc({"type": "ip_address", "value": "203.0.113.5"})

        assert result["geolocation"] == {"country": "NL"}

    def test_a_stored_record_without_a_country_reports_none(self, agent, cti):
        seed_ioc(cti)
        result = agent.enrich_ioc({"type": "ip_address", "value": "203.0.113.5"})
        assert "geolocation" not in result

    def test_the_country_is_never_from_the_old_random_set(self, agent, cti):
        """The old code chose from ["US", "RU", "CN", "BR", "IN"]."""
        seed_ioc(cti)
        countries = {
            agent.enrich_ioc({"type": "ip_address", "value": "203.0.113.5"})
            .get("geolocation", {})
            .get("country")
            for _ in range(50)
        }
        assert countries == {None}


class TestActorTracking:
    def test_an_unknown_actor_is_reported_as_unknown(self, agent):
        result = agent.track_threat_actor("APT-NOBODY", {})

        assert result["known"] is False
        assert result["activity_count"] == 0
        assert result["primary_ttps"] == []
        assert result["associated_campaigns"] == []

    def test_a_known_actor_reports_stored_data(self, agent, cti):
        cti.add_actor(
            ThreatActor(
                actor_id="actor-1",
                name="APT-REAL",
                category=ThreatCategory.CRIMEWARE,
                capabilities=["credential-theft"],
                confidence=0.77,
            )
        )
        cti.add_campaign(
            Campaign(
                campaign_id="camp-1",
                name="Operation Real",
                description="",
                actors=["actor-1"],
            )
        )

        result = agent.track_threat_actor("APT-REAL", {})
        assert result["known"] is True
        assert result["activity_count"] == 1
        assert result["primary_ttps"] == ["credential-theft"]
        assert result["associated_campaigns"] == ["Operation Real"]
        assert result["confidence"] == pytest.approx(0.77)

    def test_an_actor_is_resolvable_by_alias(self, agent, cti):
        cti.add_actor(
            ThreatActor(
                actor_id="actor-1",
                name="APT-REAL",
                category=ThreatCategory.CRIMEWARE,
                aliases=["Nightjar"],
            )
        )
        assert agent.track_threat_actor("Nightjar", {})["known"] is True

    def test_campaign_names_are_never_invented(self, agent):
        """The old code returned campaign_<random int>."""
        result = agent.track_threat_actor("APT-NOBODY", {})
        assert not any(
            str(name).startswith("campaign_") for name in result["associated_campaigns"]
        )
