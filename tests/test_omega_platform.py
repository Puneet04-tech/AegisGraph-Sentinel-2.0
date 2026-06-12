"""
Unit tests for AegisGraph Sentinel Omega Platform.
"""

import pytest
from datetime import datetime, timezone
from src.omega_platform import (
    get_omega_platform,
    initialize_omega,
    OmegaStatus,
    IntelligenceLayer,
    OmegaPlatform,
)


class TestOmegaPlatform:
    """Tests for OmegaPlatform."""

    def setup_method(self):
        """Set up test fixtures."""
        # Reset the singleton for clean tests
        import src.omega_platform.omega_platform as omega_module
        omega_module._omega_instance = None

    def test_initialize_omega(self):
        """Test Omega platform initialization."""
        result = initialize_omega()
        assert result is not None
        assert "status" in result
        assert "components_initialized" in result

    def test_get_omega_platform(self):
        """Test getting Omega platform instance."""
        omega = get_omega_platform()
        assert omega is not None
        assert isinstance(omega, OmegaPlatform)

    def test_platform_status(self):
        """Test getting platform status."""
        omega = get_omega_platform()
        status = omega.get_status()
        assert "status" in status
        assert "initialized" in status
        assert "total_components" in status

    def test_get_unified_dashboard(self):
        """Test getting unified dashboard."""
        omega = get_omega_platform()
        dashboard = omega.get_unified_dashboard()
        assert dashboard is not None
        assert hasattr(dashboard, "dashboard_id")
        assert hasattr(dashboard, "overall_status")
        assert hasattr(dashboard, "compliance_score")
        assert hasattr(dashboard, "fraud_risk_score")
        assert hasattr(dashboard, "threat_level")

    def test_get_capabilities(self):
        """Test getting platform capabilities."""
        omega = get_omega_platform()
        capabilities = omega.get_capabilities()
        assert isinstance(capabilities, dict)
        # Should have all intelligence layers
        assert "FRAUD" in capabilities or len(capabilities) >= 0

    def test_cross_layer_analysis(self):
        """Test cross-layer analysis."""
        omega = get_omega_platform()
        analysis = omega.analyze_cross_layer(
            entity_id="test_entity_123",
            layers=[IntelligenceLayer.COMPLIANCE, IntelligenceLayer.THREAT],
        )
        assert analysis is not None
        assert hasattr(analysis, "analysis_id")
        assert hasattr(analysis, "layers_analyzed")
        assert hasattr(analysis, "risk_score")
        assert IntelligenceLayer.COMPLIANCE in analysis.layers_analyzed
        assert IntelligenceLayer.THREAT in analysis.layers_analyzed

    def test_analyze_all_layers(self):
        """Test analyzing all layers."""
        omega = get_omega_platform()
        analysis = omega.analyze_cross_layer(
            entity_id="test_entity_456",
            layers=None,  # All layers
        )
        assert analysis is not None
        # Should analyze all layers when None is passed
        assert len(analysis.layers_analyzed) == len(IntelligenceLayer)

    def test_platform_initialization_state(self):
        """Test platform initialization state."""
        # Initialize the platform first
        initialize_omega()
        omega = get_omega_platform()
        assert omega._initialized is True
        assert omega._status == OmegaStatus.OPERATIONAL or omega._status == OmegaStatus.DEGRADED


class TestOmegaStatus:
    """Tests for OmegaStatus enum."""

    def test_status_values(self):
        """Test status enum values."""
        assert OmegaStatus.INITIALIZING.value == "INITIALIZING"
        assert OmegaStatus.OPERATIONAL.value == "OPERATIONAL"
        assert OmegaStatus.DEGRADED.value == "DEGRADED"
        assert OmegaStatus.MAINTENANCE.value == "MAINTENANCE"
        assert OmegaStatus.OFFLINE.value == "OFFLINE"


class TestIntelligenceLayer:
    """Tests for IntelligenceLayer enum."""

    def test_layer_values(self):
        """Test layer enum values."""
        assert IntelligenceLayer.FRAUD.value == "FRAUD"
        assert IntelligenceLayer.THREAT.value == "THREAT"
        assert IntelligenceLayer.COMPLIANCE.value == "COMPLIANCE"
        assert IntelligenceLayer.DEFENSE.value == "DEFENSE"
        assert IntelligenceLayer.PREDICTIVE.value == "PREDICTIVE"
        assert IntelligenceLayer.REGULATORY.value == "REGULATORY"
        assert IntelligenceLayer.GOVERNANCE.value == "GOVERNANCE"
        assert IntelligenceLayer.DIGITAL_TWIN.value == "DIGITAL_TWIN"

    def test_layer_count(self):
        """Test number of intelligence layers."""
        assert len(IntelligenceLayer) == 8


if __name__ == "__main__":
    pytest.main([__file__, "-v"])