"""
Tests for AegisGraph Sentinel Infinity Platform.
"""

import pytest

from src.infinity_platform import (
    Component,
    ComponentType,
    CrossDomainCorrelation,
    InfinityStore,
    get_infinity_store,
    reset_infinity_store,
    InfinityEngine,
    IntegrationStatus,
    RiskLevel,
    UnifiedIntelligence,
)


class TestModels:
    """Test data models."""

    def test_component_creation(self):
        """Test component creation."""
        comp = Component(
            component_id="comp-1",
            component_type=ComponentType.FRAUD_DETECTION,
            name="Fraud Detection Engine",
        )
        assert comp.component_id == "comp-1"
        assert comp.component_type == ComponentType.FRAUD_DETECTION

    def test_unified_intelligence_creation(self):
        """Test unified intelligence creation."""
        intel = UnifiedIntelligence(
            intel_id="intel-1",
            intelligence_type="threat",
            title="Coordinated Attack",
            description="Cross-domain threat detected",
            severity=RiskLevel.HIGH,
            sources=["fraud", "cyber"],
        )
        assert intel.intel_id == "intel-1"
        assert len(intel.sources) == 2


class TestStore:
    """Test infinity store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_infinity_store()
        self.store = get_infinity_store()

    def test_add_component(self):
        """Test adding a component."""
        comp = Component(
            component_id="comp-1",
            component_type=ComponentType.AML,
            name="AML Engine",
        )
        self.store.add_component(comp)
        
        retrieved = self.store.get_component("comp-1")
        assert retrieved is not None


class TestInfinityEngine:
    """Test infinity engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_infinity_store()
        self.engine = InfinityEngine()

    def test_register_component(self):
        """Test registering a component."""
        comp = self.engine.register_component(
            component_type="fraud_detection",
            name="Fraud Engine",
        )
        
        assert comp.component_id is not None
        assert comp.component_type == ComponentType.FRAUD_DETECTION

    def test_add_unified_intelligence(self):
        """Test adding unified intelligence."""
        intel = self.engine.add_unified_intelligence(
            sources=["fraud_detection", "cyber_security"],
            intelligence_type="campaign",
            title="Multi-Domain Attack",
            description="Coordinated attack across domains",
            severity="high",
            confidence=0.9,
        )
        
        assert intel.intel_id is not None
        assert len(intel.sources) == 2

    def test_correlate_intelligence(self):
        """Test correlating intelligence."""
        intel1 = self.engine.add_unified_intelligence(
            sources=["fraud"],
            intelligence_type="fraud",
            title="Suspicious Account",
            description="Account showing fraud indicators",
            severity="medium",
        )
        
        intel2 = self.engine.add_unified_intelligence(
            sources=["cyber"],
            intelligence_type="threat",
            title="Compromised System",
            description="System compromise detected",
            severity="high",
        )
        
        correlation = self.engine.correlate_intelligence(
            intelligence_ids=[intel1.intel_id, intel2.intel_id],
            correlation_type="cross_domain",
            description="Fraud and cyber threat correlated",
        )
        
        assert correlation.correlation_id is not None
        assert len(correlation.related_intelligence) == 2

    def test_search_unified_intelligence(self):
        """Test searching unified intelligence."""
        self.engine.add_unified_intelligence(
            sources=["fraud"],
            intelligence_type="fraud",
            title="Mule Account Detected",
            description="Suspicious money transfer activity",
            severity="high",
        )
        
        results = self.engine.search_unified_intelligence("mule")
        assert len(results) >= 1

    def test_get_executive_dashboard(self):
        """Test getting executive dashboard."""
        self.engine.register_component(
            component_type="fraud_detection",
            name="Fraud Engine",
        )
        self.engine.register_component(
            component_type="cyber_security",
            name="Cyber Engine",
        )
        
        dashboard = self.engine.get_executive_dashboard()
        
        assert "platform_health" in dashboard
        assert "threat_summary" in dashboard
        assert "components" in dashboard

    def test_sync_component(self):
        """Test syncing a component."""
        comp = self.engine.register_component(
            component_type="aml",
            name="AML Engine",
        )
        
        result = self.engine.sync_component(comp.component_id)
        assert result is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])