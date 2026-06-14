"""
Tests for Global AI Fraud Defense Network.
"""

import asyncio
import pytest

from src.global_defense_network import (
    CrossCorrelation,
    DefenseResponse,
    FraudCampaign,
    Institution,
    IntelligenceSharingLevel,
    ThreatCampaignStatus,
    TrustLevel,
    GlobalDefenseStore,
    get_global_defense_store,
    reset_global_defense_store,
    FederatedIntelligenceHub,
    ThreatCorrelationEngine,
    ThreatForecastEngine,
    GlobalDefenseNetwork,
    ThreatIntelligence,
)


class TestModels:
    """Test data models."""

    def test_institution_creation(self):
        """Test institution creation."""
        institution = Institution(
            institution_id="inst-1",
            name="Test Bank",
            trust_level=TrustLevel.TRUSTED,
        )
        assert institution.institution_id == "inst-1"
        assert institution.trust_level == TrustLevel.TRUSTED

    def test_fraud_campaign_creation(self):
        """Test fraud campaign creation."""
        campaign = FraudCampaign(
            campaign_id="camp-1",
            name="Operation Fraud Storm",
            threat_level=0.8,
        )
        assert campaign.campaign_id == "camp-1"
        assert campaign.threat_level > 0.5


class TestStore:
    """Test global defense store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_global_defense_store()
        self.store = get_global_defense_store()

    def test_institution_storage(self):
        """Test storing institutions."""
        institution = Institution(
            institution_id="inst-1",
            name="Test Bank",
        )
        self.store.add_institution(institution)
        
        retrieved = self.store.get_institution("inst-1")
        assert retrieved is not None
        assert retrieved.name == "Test Bank"

    def test_get_trusted_institutions(self):
        """Test getting trusted institutions."""
        for i in range(3):
            inst = Institution(
                institution_id=f"inst-{i}",
                name=f"Bank {i}",
                trust_level=TrustLevel.TRUSTED if i < 2 else TrustLevel.PROVISIONAL,
            )
            self.store.add_institution(inst)
        
        trusted = self.store.get_trusted_institutions(TrustLevel.TRUSTED)
        assert len(trusted) == 2

    def test_network_metrics(self):
        """Test network metrics."""
        inst = Institution(
            institution_id="inst-1",
            name="Test Bank",
            reputation_score=0.8,
        )
        self.store.add_institution(inst)
        
        metrics = self.store.get_network_metrics()
        assert metrics.total_institutions == 1
        assert metrics.avg_trust_score > 0


class TestFederatedHub:
    """Test federated intelligence hub."""

    def setup_method(self):
        """Reset store before each test."""
        reset_global_defense_store()
        self.hub = FederatedIntelligenceHub()

    def test_share_intelligence(self):
        """Test sharing intelligence."""
        result = asyncio.run(self.hub.share_intelligence(
            source_institution="bank-1",
            threat_type="phishing",
            indicators=[{"ip": "192.168.1.1"}, {"email": "test@example.com"}],
            confidence=0.8,
            sharing_level="anonymized",
        ))
        
        assert result.intelligence_id is not None
        assert result.confidence == 0.8

    def test_get_network_intelligence(self):
        """Test getting network intelligence."""
        asyncio.run(self.hub.share_intelligence(
            source_institution="bank-1",
            threat_type="phishing",
            indicators=[{"ip": "10.0.0.1"}],
            confidence=0.7,
        ))
        
        intelligence = self.hub.get_network_intelligence(min_confidence=0.5)
        assert len(intelligence) == 1


class TestThreatCorrelationEngine:
    """Test threat correlation engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_global_defense_store()
        self.engine = ThreatCorrelationEngine()

    def test_correlate_threats(self):
        """Test correlating threats."""
        store = get_global_defense_store()
        
        intel1 = ThreatIntelligence(
            intelligence_id="intel-1",
            source_institution="bank-1",
            threat_type="fraud",
            indicators=[{"hash": "abc123"}],
            confidence=0.8,
        )
        intel2 = ThreatIntelligence(
            intelligence_id="intel-2",
            source_institution="bank-2",
            threat_type="fraud",
            indicators=[{"hash": "abc123"}],
            confidence=0.7,
        )
        store.store_intelligence(intel1)
        store.store_intelligence(intel2)
        
        result = asyncio.run(self.engine.correlate_threats("bank-1", "bank-2"))
        
        assert result.correlation_id is not None
        assert result.confidence > 0
        assert any("abc123" in ind for ind in result.shared_indicators)


class TestThreatForecastEngine:
    """Test threat forecast engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_global_defense_store()
        self.engine = ThreatForecastEngine()

    def test_generate_forecast(self):
        """Test generating forecasts."""
        store = get_global_defense_store()
        
        intel = ThreatIntelligence(
            intelligence_id="intel-1",
            source_institution="bank-1",
            threat_type="phishing",
            indicators=[{"ip": "10.0.0.1"}],
            confidence=0.8,
        )
        store.store_intelligence(intel)
        
        forecasts = asyncio.run(self.engine.generate_forecast())
        assert isinstance(forecasts, list)

    def test_forecast_summary(self):
        """Test forecast summary."""
        summary = self.engine.get_forecast_summary()
        assert "total_forecasts" in summary


class TestGlobalDefenseNetwork:
    """Test main service."""

    def setup_method(self):
        """Reset store before each test."""
        reset_global_defense_store()
        self.network = GlobalDefenseNetwork()

    def test_add_institution(self):
        """Test adding institution."""
        result = self.network.add_institution(
            institution_id="bank-1",
            name="Test Bank",
            trust_level="trusted",
        )
        
        assert result["institution_id"] == "bank-1"
        assert result["status"] == "joined"

    def test_share_intelligence(self):
        """Test sharing intelligence."""
        result = asyncio.run(self.network.share_intelligence(
            institution_id="bank-1",
            threat_type="phishing",
            indicators=[{"ip": "192.168.1.1"}],
            confidence=0.8,
        ))
        
        assert "intelligence_id" in result
        assert result["status"] == "shared"

    def test_get_network_status(self):
        """Test getting network status."""
        result = asyncio.run(self.network.get_network_status())
        
        assert "metrics" in result
        assert "contributions" in result

    def test_get_dashboard(self):
        """Test getting dashboard."""
        result = asyncio.run(self.network.get_dashboard())
        
        assert "network_metrics" in result
        assert "forecasts" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])