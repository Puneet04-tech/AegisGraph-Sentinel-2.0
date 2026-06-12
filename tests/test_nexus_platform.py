"""
Tests for Nexus Platform Module
"""
import pytest
from datetime import datetime, timezone

from src.nexus_platform import (
    NexusPlatform,
    get_nexus_platform,
    IntelligenceLayer,
    NexusStatus,
    IntegrationStatus,
    LayerStatus,
    NexusCapability,
    NexusDashboard,
    CrossLayerAnalysis,
)


class TestNexusPlatform:
    """Tests for NexusPlatform."""
    
    def setup_method(self):
        self.platform = NexusPlatform()
    
    def test_initialization(self):
        """Test platform initialization."""
        assert self.platform is not None
        assert self.platform.platform_id is not None
        assert self.platform.status == NexusStatus.OPERATIONAL
    
    def test_get_layer_status(self):
        """Test getting layer status."""
        status = self.platform.get_layer_status(IntelligenceLayer.FRAUD)
        assert status is not None
        assert status.layer == IntelligenceLayer.FRAUD
    
    def test_update_layer_status(self):
        """Test updating layer status."""
        self.platform.update_layer_status(
            layer=IntelligenceLayer.THREAT,
            status=IntegrationStatus.CONNECTED,
            metrics={"requests": 1000},
        )
        
        status = self.platform.get_layer_status(IntelligenceLayer.THREAT)
        assert status.status == IntegrationStatus.CONNECTED
        assert status.metrics.get("requests") == 1000
    
    def test_get_capability(self):
        """Test getting a capability."""
        cap = self.platform.get_capability("fraud-detection")
        assert cap is not None
        assert cap.name == "Real-time Fraud Detection"
    
    def test_get_enabled_capabilities(self):
        """Test getting enabled capabilities."""
        caps = self.platform.get_enabled_capabilities()
        assert len(caps) >= 1
        assert all(c.enabled for c in caps)
    
    def test_cross_layer_analysis(self):
        """Test cross-layer analysis."""
        analysis = self.platform.cross_layer_analysis(
            entity_id="entity-123",
            layers=[IntelligenceLayer.FRAUD, IntelligenceLayer.THREAT],
        )
        
        assert analysis is not None
        assert analysis.target_entity == "entity-123"
        assert len(analysis.source_layers) == 2
        assert analysis.risk_score >= 0.0
    
    def test_generate_dashboard(self):
        """Test dashboard generation."""
        dashboard = self.platform.generate_dashboard()
        
        assert dashboard is not None
        assert dashboard.overall_status == NexusStatus.OPERATIONAL
        assert len(dashboard.layer_statuses) == len(IntelligenceLayer)
    
    def test_get_platform_info(self):
        """Test getting platform info."""
        info = self.platform.get_platform_info()
        
        assert info["platform_name"] == "AegisGraph Sentinel Nexus"
        assert "version" in info
        assert "layers" in info
        assert "capabilities" in info
    
    def test_all_layers_initialized(self):
        """Test all intelligence layers are initialized."""
        for layer in IntelligenceLayer:
            status = self.platform.get_layer_status(layer)
            assert status.layer == layer


class TestModels:
    """Tests for model classes."""
    
    def test_layer_status_to_dict(self):
        """Test LayerStatus serialization."""
        status = LayerStatus(
            layer=IntelligenceLayer.FRAUD,
            status=IntegrationStatus.CONNECTED,
        )
        
        data = status.to_dict()
        assert data["layer"] == "FRAUD"
        assert data["status"] == "CONNECTED"
    
    def test_nexus_capability_to_dict(self):
        """Test NexusCapability serialization."""
        cap = NexusCapability(
            capability_id="test-cap",
            name="Test Capability",
            description="Test description",
            layers=[IntelligenceLayer.FRAUD],
            endpoints=["/test"],
        )
        
        data = cap.to_dict()
        assert data["capability_id"] == "test-cap"
        assert "FRAUD" in data["layers"]
    
    def test_nexus_dashboard_to_dict(self):
        """Test NexusDashboard serialization."""
        dashboard = NexusDashboard(
            dashboard_id="dash-1",
            overall_status=NexusStatus.OPERATIONAL,
        )
        
        data = dashboard.to_dict()
        assert data["dashboard_id"] == "dash-1"
        assert data["overall_status"] == "OPERATIONAL"
    
    def test_cross_layer_analysis_to_dict(self):
        """Test CrossLayerAnalysis serialization."""
        analysis = CrossLayerAnalysis(
            analysis_id="analysis-1",
            source_layers=[IntelligenceLayer.FRAUD],
            target_entity="entity-1",
            insights=["Insight 1"],
            risk_score=0.5,
            recommendations=["Rec 1"],
            confidence=0.9,
        )
        
        data = analysis.to_dict()
        assert data["analysis_id"] == "analysis-1"
        assert data["risk_score"] == 0.5
    
    def test_intelligence_layer_values(self):
        """Test IntelligenceLayer enum values."""
        assert IntelligenceLayer.FRAUD.value == "FRAUD"
        assert IntelligenceLayer.THREAT.value == "THREAT"
        assert len(IntelligenceLayer) == 12
    
    def test_nexus_status_values(self):
        """Test NexusStatus enum values."""
        assert NexusStatus.OPERATIONAL.value == "OPERATIONAL"
        assert NexusStatus.DEGRADED.value == "DEGRADED"
    
    def test_integration_status_values(self):
        """Test IntegrationStatus enum values."""
        assert IntegrationStatus.CONNECTED.value == "CONNECTED"
        assert IntegrationStatus.AVAILABLE.value == "AVAILABLE"


class TestGlobalInstance:
    """Tests for global instance."""
    
    def test_get_nexus_platform(self):
        """Test getting global platform instance."""
        platform = get_nexus_platform()
        assert platform is not None
        assert isinstance(platform, NexusPlatform)
    
    def test_singleton_behavior(self):
        """Test singleton behavior."""
        p1 = get_nexus_platform()
        p2 = get_nexus_platform()
        assert p1 is p2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])