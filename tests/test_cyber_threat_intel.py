"""
Tests for Cyber Threat Intelligence Platform.
"""

import pytest

from src.cyber_threat_intel import (
    Campaign,
    FeedSource,
    IOC,
    IOCType,
    ThreatActor,
    ThreatCategory,
    ThreatLevel,
    CTIStore,
    get_cti_store,
    reset_cti_store,
    CTIEngine,
)


class TestModels:
    """Test data models."""

    def test_ioc_creation(self):
        """Test IOC creation."""
        ioc = IOC(
            ioc_id="ioc-1",
            indicator_type=IOCType.IP,
            value="192.168.1.1",
            threat_level=ThreatLevel.HIGH,
        )
        assert ioc.ioc_id == "ioc-1"
        assert ioc.indicator_type == IOCType.IP

    def test_threat_actor_creation(self):
        """Test threat actor creation."""
        actor = ThreatActor(
            actor_id="actor-1",
            name="APT-29",
            category=ThreatCategory.APT,
        )
        assert actor.actor_id == "actor-1"


class TestStore:
    """Test CTI store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_cti_store()
        self.store = get_cti_store()

    def test_add_ioc(self):
        """Test adding an IOC."""
        ioc = IOC(
            ioc_id="ioc-1",
            indicator_type=IOCType.DOMAIN,
            value="malicious.com",
            threat_level=ThreatLevel.CRITICAL,
        )
        self.store.add_ioc(ioc)
        
        retrieved = self.store.get_ioc("ioc-1")
        assert retrieved is not None


class TestCTIEngine:
    """Test CTI engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_cti_store()
        self.engine = CTIEngine()

    def test_add_ioc(self):
        """Test adding an IOC."""
        ioc = self.engine.add_ioc(
            indicator_type="ip",
            value="10.0.0.1",
            threat_level="high",
            confidence=0.8,
        )
        
        assert ioc.ioc_id is not None
        assert ioc.indicator_type == IOCType.IP

    def test_search_iocs(self):
        """Test searching IOCs."""
        self.engine.add_ioc(
            indicator_type="domain",
            value="evil.com",
            threat_level="critical",
        )
        
        results = self.engine.search_iocs("evil")
        assert len(results) >= 1

    def test_add_threat_actor(self):
        """Test adding threat actor."""
        actor = self.engine.add_threat_actor(
            name="Lazarus Group",
            category="apt",
            motivation=["financial", "espionage"],
        )
        
        assert actor.actor_id is not None

    def test_add_campaign(self):
        """Test adding campaign."""
        campaign = self.engine.add_campaign(
            name="Operation Shadow",
            description="Advanced persistent threat operation",
        )
        
        assert campaign.campaign_id is not None

    def test_enrich_ioc(self):
        """Test enriching IOC."""
        ioc = self.engine.add_ioc(
            indicator_type="ip",
            value="1.2.3.4",
            threat_level="high",
        )
        
        result = self.engine.enrich_ioc(ioc.ioc_id)
        
        assert result["success"] is True

    def test_calculate_threat_score(self):
        """Test calculating threat score."""
        self.engine.add_ioc(
            indicator_type="domain",
            value="suspicious.com",
            threat_level="critical",
        )
        
        score = self.engine.calculate_threat_score("domain", "suspicious.com")
        
        assert score.score_id is not None

    def test_get_dashboard(self):
        """Test getting dashboard."""
        result = self.engine.get_dashboard()
        
        assert "total_iocs" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])