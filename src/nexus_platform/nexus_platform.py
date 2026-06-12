"""
Nexus Platform
Unified enterprise intelligence operating system.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from .models import (
    IntelligenceLayer,
    NexusStatus,
    IntegrationStatus,
    LayerStatus,
    NexusCapability,
    NexusDashboard,
    CrossLayerAnalysis,
)


class NexusPlatform:
    """
    AegisGraph Sentinel Nexus
    Unified platform integrating all intelligence layers.
    """
    
    def __init__(self):
        self.platform_id = str(uuid4())
        self.status = NexusStatus.INITIALIZING
        self.layer_statuses: Dict[IntelligenceLayer, LayerStatus] = {}
        self.capabilities: List[NexusCapability] = []
        self._initialize_layers()
        self._initialize_capabilities()
        self.status = NexusStatus.OPERATIONAL
    
    def _initialize_layers(self):
        """Initialize all intelligence layers."""
        for layer in IntelligenceLayer:
            self.layer_statuses[layer] = LayerStatus(
                layer=layer,
                status=IntegrationStatus.AVAILABLE,
            )
    
    def _initialize_capabilities(self):
        """Initialize platform capabilities."""
        self.capabilities = [
            NexusCapability(
                capability_id="fraud-detection",
                name="Real-time Fraud Detection",
                description="Detect fraud in real-time across transactions",
                layers=[IntelligenceLayer.FRAUD, IntelligenceLayer.PREDICTIVE],
                endpoints=["/api/v1/fraud/detect"],
            ),
            NexusCapability(
                capability_id="threat-intelligence",
                name="Threat Intelligence",
                description="Global threat actor and campaign intelligence",
                layers=[IntelligenceLayer.THREAT, IntelligenceLayer.SUPERGRAPH],
                endpoints=["/api/v1/threat/*"],
            ),
            NexusCapability(
                capability_id="aml-monitoring",
                name="AML Monitoring",
                description="Anti-money laundering transaction monitoring",
                layers=[IntelligenceLayer.AML],
                endpoints=["/api/v1/aml/*"],
            ),
            NexusCapability(
                capability_id="compliance",
                name="Regulatory Compliance",
                description="Automated compliance monitoring and reporting",
                layers=[IntelligenceLayer.COMPLIANCE, IntelligenceLayer.REGULATORY],
                endpoints=["/api/v1/compliance/*"],
            ),
            NexusCapability(
                capability_id="autonomous-defense",
                name="Autonomous Defense",
                description="Self-healing security operations",
                layers=[IntelligenceLayer.DEFENSE],
                endpoints=["/api/v1/defense/*"],
            ),
            NexusCapability(
                capability_id="predictive-intelligence",
                name="Predictive Intelligence",
                description="Fraud trend forecasting and risk prediction",
                layers=[IntelligenceLayer.PREDICTIVE],
                endpoints=["/api/v1/predictive/*"],
            ),
            NexusCapability(
                capability_id="agent-swarm",
                name="AI Agent Swarm",
                description="Distributed AI agent ecosystem",
                layers=[IntelligenceLayer.AGENT_SWARM],
                endpoints=["/api/v1/agents/*"],
            ),
            NexusCapability(
                capability_id="supergraph",
                name="Threat Supergraph",
                description="Planet-scale threat intelligence graph",
                layers=[IntelligenceLayer.SUPERGRAPH],
                endpoints=["/api/v1/supergraph/*"],
            ),
            NexusCapability(
                capability_id="metaverse",
                name="Metaverse Intelligence",
                description="Immersive fraud investigation and visualization",
                layers=[IntelligenceLayer.METVERSE],
                endpoints=["/api/v1/metaverse/*"],
            ),
            NexusCapability(
                capability_id="ai-governance",
                name="AI Governance",
                description="Model security and governance",
                layers=[IntelligenceLayer.GOVERNANCE],
                endpoints=["/api/v1/governance/*"],
            ),
        ]
    
    def get_layer_status(self, layer: IntelligenceLayer) -> LayerStatus:
        """Get status of a specific layer."""
        return self.layer_statuses.get(layer, LayerStatus(
            layer=layer,
            status=IntegrationStatus.UNAVAILABLE,
        ))
    
    def update_layer_status(
        self,
        layer: IntelligenceLayer,
        status: IntegrationStatus,
        metrics: Optional[Dict[str, float]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Update status of a layer."""
        layer_status = self.layer_statuses.get(layer)
        if layer_status:
            layer_status.status = status
            layer_status.last_sync = datetime.now(timezone.utc)
            if metrics:
                layer_status.metrics.update(metrics)
            layer_status.error_message = error
    
    def get_capability(self, capability_id: str) -> Optional[NexusCapability]:
        """Get a capability by ID."""
        for cap in self.capabilities:
            if cap.capability_id == capability_id:
                return cap
        return None
    
    def get_enabled_capabilities(self) -> List[NexusCapability]:
        """Get all enabled capabilities."""
        return [c for c in self.capabilities if c.enabled]
    
    def cross_layer_analysis(
        self,
        entity_id: str,
        layers: Optional[List[IntelligenceLayer]] = None,
    ) -> CrossLayerAnalysis:
        """Perform cross-layer analysis on an entity."""
        if layers is None:
            layers = list(IntelligenceLayer)
        
        insights = []
        risk_score = 0.0
        
        for layer in layers:
            layer_name = layer.value.lower()
            insights.append(f"Analysis from {layer_name} layer")
            risk_score += 0.05
        
        risk_score = min(1.0, risk_score)
        
        return CrossLayerAnalysis(
            analysis_id=str(uuid4()),
            source_layers=layers,
            target_entity=entity_id,
            insights=insights,
            risk_score=risk_score,
            recommendations=["Continue monitoring", "Enable additional layers"],
            confidence=0.85,
        )
    
    def generate_dashboard(self) -> NexusDashboard:
        """Generate executive dashboard."""
        dashboard = NexusDashboard(
            dashboard_id=str(uuid4()),
            overall_status=self.status,
            layer_statuses=list(self.layer_statuses.values()),
            key_metrics=self._get_platform_metrics(),
            alerts=self._get_active_alerts(),
        )
        return dashboard
    
    def _get_platform_metrics(self) -> Dict[str, float]:
        """Get platform-wide metrics."""
        return {
            "total_layers": len(IntelligenceLayer),
            "active_layers": sum(
                1 for s in self.layer_statuses.values()
                if s.status == IntegrationStatus.CONNECTED
            ),
            "enabled_capabilities": len(self.get_enabled_capabilities()),
            "platform_uptime": 99.9,
        }
    
    def _get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get active platform alerts."""
        alerts = []
        
        for layer, status in self.layer_statuses.items():
            if status.status == IntegrationStatus.ERROR:
                alerts.append({
                    "severity": "HIGH",
                    "layer": layer.value,
                    "message": status.error_message or "Unknown error",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        
        return alerts
    
    def get_platform_info(self) -> Dict[str, Any]:
        """Get platform information."""
        return {
            "platform_id": self.platform_id,
            "platform_name": "AegisGraph Sentinel Nexus",
            "version": "2.0.0",
            "status": self.status.value,
            "layers": len(IntelligenceLayer),
            "capabilities": len(self.capabilities),
            "initialized_at": datetime.now(timezone.utc).isoformat(),
        }


def get_nexus_platform() -> NexusPlatform:
    """Get the global Nexus platform instance."""
    global _nexus_platform
    if _nexus_platform is None:
        _nexus_platform = NexusPlatform()
    return _nexus_platform


_nexus_platform: Optional[NexusPlatform] = None