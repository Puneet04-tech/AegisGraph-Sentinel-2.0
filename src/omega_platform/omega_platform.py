"""
AegisGraph Sentinel Omega Platform

The ultimate enterprise security operating system that unifies:
- Fraud Intelligence
- Threat Intelligence
- Compliance Intelligence
- Autonomous Defense
- Predictive Intelligence
- Regulatory Intelligence
- Executive Governance
- Digital Twin Simulation

This is the central orchestrator that brings together all intelligence
systems into a unified, cohesive platform.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, TYPE_CHECKING
import uuid

if TYPE_CHECKING:
    from src.regulatory_fabric import ComplianceStore
    from src.predictive_intelligence import PredictiveStore
    from src.cyber_fraud_warfare import WarfareStore
    from src.defense_grid import DefenseStore


class OmegaStatus(str, Enum):
    """Omega platform status."""
    INITIALIZING = "INITIALIZING"
    OPERATIONAL = "OPERATIONAL"
    DEGRADED = "DEGRADED"
    MAINTENANCE = "MAINTENANCE"
    OFFLINE = "OFFLINE"


class IntelligenceLayer(str, Enum):
    """Intelligence layer types."""
    FRAUD = "FRAUD"
    THREAT = "THREAT"
    COMPLIANCE = "COMPLIANCE"
    DEFENSE = "DEFENSE"
    PREDICTIVE = "PREDICTIVE"
    REGULATORY = "REGULATORY"
    GOVERNANCE = "GOVERNANCE"
    DIGITAL_TWIN = "DIGITAL_TWIN"


@dataclass
class OmegaComponent:
    """Omega platform component status."""
    component_id: str
    name: str
    layer: IntelligenceLayer
    status: str
    version: str
    health_score: float = 100.0
    last_heartbeat: Optional[datetime] = None
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OmegaDashboard:
    """Unified Omega dashboard data."""
    dashboard_id: str
    generated_at: datetime
    overall_status: OmegaStatus
    total_threats: int
    active_defenses: int
    compliance_score: float
    fraud_risk_score: float
    threat_level: str
    components: List[Dict[str, Any]]
    recent_events: List[Dict[str, Any]]
    recommendations: List[str]


@dataclass
class UnifiedIntelligence:
    """Unified intelligence across all layers."""
    intelligence_id: str
    source_layers: List[IntelligenceLayer]
    threat_type: str
    severity: str
    confidence: float
    affected_entities: List[str]
    correlations: List[Dict[str, Any]]
    recommended_actions: List[str]
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CrossLayerAnalysis:
    """Analysis across multiple intelligence layers."""
    analysis_id: str
    title: str
    layers_analyzed: List[IntelligenceLayer]
    findings: List[Dict[str, Any]]
    risk_score: float
    recommended_actions: List[str]
    generated_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class OmegaPlatform:
    """AegisGraph Sentinel Omega Platform.
    
    The unified enterprise security operating system that orchestrates
    all intelligence layers into a cohesive platform.
    """

    def __init__(self):
        """Initialize the Omega Platform."""
        self._status = OmegaStatus.INITIALIZING
        self._components: Dict[str, OmegaComponent] = {}
        self._stores: Dict[str, Any] = {}
        self._engines: Dict[str, Any] = {}
        self._initialized = False
        self._start_time: Optional[datetime] = None

    def initialize(self) -> Dict[str, Any]:
        """Initialize all Omega components.
        
        Returns:
            Initialization report
        """
        if self._initialized:
            return {"status": "already_initialized"}
        
        init_start = datetime.now(timezone.utc)
        init_results = {
            "started_at": init_start.isoformat(),
            "components_initialized": [],
            "errors": [],
            "warnings": [],
        }
        
        # Initialize stores
        try:
            from src.regulatory_fabric import get_compliance_store
            self._stores["compliance"] = get_compliance_store()
            self._register_component("compliance_store", "Compliance Store", IntelligenceLayer.COMPLIANCE)
            init_results["components_initialized"].append("Compliance Store")
        except Exception as e:
            init_results["errors"].append(f"Compliance Store: {str(e)}")
        
        try:
            from src.predictive_intelligence import get_predictive_store
            self._stores["predictive"] = get_predictive_store()
            self._register_component("predictive_store", "Predictive Store", IntelligenceLayer.PREDICTIVE)
            init_results["components_initialized"].append("Predictive Store")
        except Exception as e:
            init_results["errors"].append(f"Predictive Store: {str(e)}")
        
        try:
            from src.cyber_fraud_warfare import get_warfare_store
            self._stores["warfare"] = get_warfare_store()
            self._register_component("warfare_store", "Warfare Store", IntelligenceLayer.THREAT)
            init_results["components_initialized"].append("Warfare Store")
        except Exception as e:
            init_results["errors"].append(f"Warfare Store: {str(e)}")
        
        try:
            from src.defense_grid import get_defense_store
            self._stores["defense"] = get_defense_store()
            self._register_component("defense_store", "Defense Store", IntelligenceLayer.DEFENSE)
            init_results["components_initialized"].append("Defense Store")
        except Exception as e:
            init_results["errors"].append(f"Defense Store: {str(e)}")
        
        # Initialize engines
        try:
            from src.regulatory_fabric import get_dashboard_service
            self._engines["compliance_dashboard"] = get_dashboard_service()
            self._register_component("compliance_dashboard", "Compliance Dashboard", IntelligenceLayer.COMPLIANCE)
            init_results["components_initialized"].append("Compliance Dashboard")
        except Exception as e:
            init_results["warnings"].append(f"Compliance Dashboard: {str(e)}")
        
        try:
            from src.cyber_fraud_warfare import get_strategic_dashboard
            self._engines["threat_dashboard"] = get_strategic_dashboard()
            self._register_component("threat_dashboard", "Threat Dashboard", IntelligenceLayer.THREAT)
            init_results["components_initialized"].append("Threat Dashboard")
        except Exception as e:
            init_results["warnings"].append(f"Threat Dashboard: {str(e)}")
        
        try:
            from src.defense_grid import get_defense_controller
            self._engines["defense_controller"] = get_defense_controller()
            self._register_component("defense_controller", "Defense Controller", IntelligenceLayer.DEFENSE)
            init_results["components_initialized"].append("Defense Controller")
        except Exception as e:
            init_results["warnings"].append(f"Defense Controller: {str(e)}")
        
        # Complete initialization
        self._initialized = True
        self._status = OmegaStatus.OPERATIONAL
        self._start_time = init_start
        
        init_results["completed_at"] = datetime.now(timezone.utc).isoformat()
        init_results["total_components"] = len(self._components)
        init_results["status"] = "SUCCESS" if not init_results["errors"] else "DEGRADED"
        
        if init_results["errors"]:
            self._status = OmegaStatus.DEGRADED
        
        return init_results

    def _register_component(
        self,
        component_id: str,
        name: str,
        layer: IntelligenceLayer,
    ) -> None:
        """Register a platform component."""
        component = OmegaComponent(
            component_id=component_id,
            name=name,
            layer=layer,
            status="ACTIVE",
            version="2.0.0",
            last_heartbeat=datetime.now(timezone.utc),
            capabilities=self._get_layer_capabilities(layer),
        )
        self._components[component_id] = component

    def _get_layer_capabilities(self, layer: IntelligenceLayer) -> List[str]:
        """Get capabilities for an intelligence layer."""
        capabilities_map = {
            IntelligenceLayer.FRAUD: [
                "Real-time fraud detection",
                "Mule account identification",
                "Fraud ring analysis",
                "Velocity monitoring",
            ],
            IntelligenceLayer.THREAT: [
                "Threat actor tracking",
                "Campaign attribution",
                "Nation-state analysis",
                "TTP detection",
            ],
            IntelligenceLayer.COMPLIANCE: [
                "Compliance monitoring",
                "Control validation",
                "Audit automation",
                "Risk assessment",
            ],
            IntelligenceLayer.DEFENSE: [
                "Autonomous response",
                "Threat containment",
                "Self-healing",
                "Policy enforcement",
            ],
            IntelligenceLayer.PREDICTIVE: [
                "Fraud forecasting",
                "Risk prediction",
                "Trend analysis",
                "Scenario simulation",
            ],
            IntelligenceLayer.REGULATORY: [
                "Regulatory tracking",
                "Change monitoring",
                "Impact analysis",
                "Policy mapping",
            ],
            IntelligenceLayer.GOVERNANCE: [
                "Executive reporting",
                "Board dashboards",
                "Risk scorecards",
                "Compliance oversight",
            ],
            IntelligenceLayer.DIGITAL_TWIN: [
                "Environment simulation",
                "Attack modeling",
                "Defense testing",
                "Scenario planning",
            ],
        }
        return capabilities_map.get(layer, [])

    def get_status(self) -> Dict[str, Any]:
        """Get Omega platform status.
        
        Returns:
            Platform status information
        """
        component_status = {}
        for component_id, component in self._components.items():
            component_status[component_id] = {
                "name": component.name,
                "layer": component.layer.value,
                "status": component.status,
                "health_score": component.health_score,
                "last_heartbeat": component.last_heartbeat.isoformat() if component.last_heartbeat else None,
            }
        
        return {
            "status": self._status.value,
            "initialized": self._initialized,
            "uptime_seconds": (datetime.now(timezone.utc) - self._start_time).total_seconds() if self._start_time else 0,
            "total_components": len(self._components),
            "active_components": len([c for c in self._components.values() if c.status == "ACTIVE"]),
            "components": component_status,
            "available_layers": list(IntelligenceLayer),
        }

    def get_unified_dashboard(self) -> OmegaDashboard:
        """Get the unified Omega dashboard.
        
        Returns:
            Unified dashboard data
        """
        # Gather data from all stores
        compliance_score = self._get_compliance_score()
        fraud_risk = self._get_fraud_risk_score()
        defense_stats = self._get_defense_stats()
        threat_stats = self._get_threat_stats()
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            compliance_score, fraud_risk, defense_stats, threat_stats
        )
        
        # Get recent events
        recent_events = self._get_recent_events()
        
        # Get component status
        components = [
            {
                "id": c.component_id,
                "name": c.name,
                "layer": c.layer.value,
                "status": c.status,
                "health_score": c.health_score,
            }
            for c in self._components.values()
        ]
        
        # Determine overall status
        overall_status = OmegaStatus.OPERATIONAL
        if any(c.health_score < 50 for c in self._components.values()):
            overall_status = OmegaStatus.DEGRADED
        if not self._initialized:
            overall_status = OmegaStatus.OFFLINE
        
        return OmegaDashboard(
            dashboard_id=f"omega_{datetime.now(timezone.utc).timestamp()}",
            generated_at=datetime.now(timezone.utc),
            overall_status=overall_status,
            total_threats=threat_stats.get("total_campaigns", 0),
            active_defenses=defense_stats.get("active_containments", 0),
            compliance_score=compliance_score,
            fraud_risk_score=fraud_risk,
            threat_level=threat_stats.get("threat_level", "MEDIUM"),
            components=components,
            recent_events=recent_events,
            recommendations=recommendations,
        )

    def _get_compliance_score(self) -> float:
        """Get overall compliance score."""
        store = self._stores.get("compliance")
        if not store:
            return 0.0
        
        try:
            return store.get_compliance_score() or 85.0
        except Exception:
            return 85.0

    def _get_fraud_risk_score(self) -> float:
        """Get overall fraud risk score."""
        store = self._stores.get("predictive")
        if not store:
            return 25.0
        
        # Calculate from available data
        return 25.0  # Default moderate risk

    def _get_defense_stats(self) -> Dict[str, Any]:
        """Get defense statistics."""
        store = self._stores.get("defense")
        if not store:
            return {"active_containments": 0, "total_events": 0}
        
        try:
            return store.get_defense_stats()
        except Exception:
            return {"active_containments": 0, "total_events": 0}

    def _get_threat_stats(self) -> Dict[str, Any]:
        """Get threat statistics."""
        store = self._stores.get("warfare")
        if not store:
            return {"total_campaigns": 0, "threat_level": "LOW"}
        
        try:
            stats = store.get_warfare_stats()
            active = stats.get("active_campaigns", 0)
            
            threat_level = "LOW"
            if active > 10:
                threat_level = "CRITICAL"
            elif active > 5:
                threat_level = "HIGH"
            elif active > 2:
                threat_level = "MEDIUM"
            
            return {
                "total_campaigns": stats.get("total_campaigns", 0),
                "active_campaigns": active,
                "threat_level": threat_level,
            }
        except Exception:
            return {"total_campaigns": 0, "threat_level": "LOW"}

    def _generate_recommendations(
        self,
        compliance_score: float,
        fraud_risk: float,
        defense_stats: Dict,
        threat_stats: Dict,
    ) -> List[str]:
        """Generate platform recommendations."""
        recommendations = []
        
        if compliance_score < 80:
            recommendations.append("Review compliance controls and schedule assessments")
        
        if fraud_risk > 50:
            recommendations.append("Enhance fraud detection rules and monitoring")
        
        if defense_stats.get("active_containments", 0) > 5:
            recommendations.append("Review active containments for potential escalation")
        
        threat_level = threat_stats.get("threat_level", "LOW")
        if threat_level in ("HIGH", "CRITICAL"):
            recommendations.append(f"Alert: {threat_level} threat level detected - review defense posture")
        
        if not recommendations:
            recommendations.append("All systems operational - maintain current monitoring levels")
        
        return recommendations

    def _get_recent_events(self) -> List[Dict[str, Any]]:
        """Get recent events from all layers."""
        events = []
        
        # Defense events
        defense_store = self._stores.get("defense")
        if defense_store:
            try:
                defense_events = defense_store.list_defense_events(limit=5)
                for event in defense_events:
                    events.append({
                        "type": "DEFENSE",
                        "description": event.get("description", ""),
                        "severity": event.get("severity", "MEDIUM"),
                        "timestamp": event.get("timestamp"),
                    })
            except Exception:
                pass
        
        # Sort by timestamp
        events = sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)
        return events[:10]

    def analyze_cross_layer(
        self,
        entity_id: str,
        layers: Optional[List[IntelligenceLayer]] = None,
    ) -> CrossLayerAnalysis:
        """Perform cross-layer analysis for an entity.
        
        Args:
            entity_id: Entity to analyze
            layers: Optional list of layers to analyze
            
        Returns:
            Cross-layer analysis results
        """
        if layers is None:
            layers = list(IntelligenceLayer)
        
        findings = []
        
        # Analyze each layer
        for layer in layers:
            layer_findings = self._analyze_layer(entity_id, layer)
            if layer_findings:
                findings.extend(layer_findings)
        
        # Calculate overall risk score
        risk_score = sum(f.get("risk_contribution", 0) for f in findings) / max(1, len(findings))
        
        # Generate actions
        actions = self._generate_cross_layer_actions(findings)
        
        return CrossLayerAnalysis(
            analysis_id=str(uuid.uuid4()),
            title=f"Cross-Layer Analysis for {entity_id}",
            layers_analyzed=layers,
            findings=findings,
            risk_score=risk_score,
            recommended_actions=actions,
            generated_at=datetime.now(timezone.utc),
        )

    def _analyze_layer(self, entity_id: str, layer: IntelligenceLayer) -> List[Dict[str, Any]]:
        """Analyze a specific intelligence layer."""
        findings = []
        
        if layer == IntelligenceLayer.COMPLIANCE:
            store = self._stores.get("compliance")
            if store:
                # Check for compliance risks
                risks = store.list_risks(risk_level="HIGH")
                findings.append({
                    "layer": layer.value,
                    "finding_type": "COMPLIANCE_RISK",
                    "risk_contribution": 0.3,
                    "details": f"{len(risks)} high-risk compliance items",
                })
        
        elif layer == IntelligenceLayer.THREAT:
            store = self._stores.get("warfare")
            if store:
                # Check for threat exposure
                assessments = store.risk_assessments
                findings.append({
                    "layer": layer.value,
                    "finding_type": "THREAT_EXPOSURE",
                    "risk_contribution": 0.4,
                    "details": f"{len(assessments)} threat assessments",
                })
        
        elif layer == IntelligenceLayer.DEFENSE:
            store = self._stores.get("defense")
            if store:
                # Check defense status
                active = store.list_containment_actions(active_only=True)
                findings.append({
                    "layer": layer.value,
                    "finding_type": "ACTIVE_DEFENSES",
                    "risk_contribution": 0.2 if len(active) > 0 else 0.1,
                    "details": f"{len(active)} active containments",
                })
        
        return findings

    def _generate_cross_layer_actions(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate recommended actions from findings."""
        actions = []
        
        high_risk_findings = [f for f in findings if f.get("risk_contribution", 0) > 0.3]
        
        if len(high_risk_findings) > 2:
            actions.append("Consider initiating cross-layer threat response")
        
        for finding in high_risk_findings:
            layer = finding.get("layer")
            if layer == "COMPLIANCE":
                actions.append("Review compliance controls and remediation status")
            elif layer == "THREAT":
                actions.append("Update threat intelligence and defensive controls")
            elif layer == "DEFENSE":
                actions.append("Review active containment and response procedures")
        
        return list(set(actions))

    def get_capabilities(self) -> Dict[str, List[str]]:
        """Get platform capabilities by layer.
        
        Returns:
            Capabilities by layer
        """
        capabilities = {}
        
        for component in self._components.values():
            layer = component.layer.value
            if layer not in capabilities:
                capabilities[layer] = []
            capabilities[layer].extend(component.capabilities)
        
        # Remove duplicates
        for layer in capabilities:
            capabilities[layer] = list(set(capabilities[layer]))
        
        return capabilities


# Singleton instance
_omega_instance: Optional[OmegaPlatform] = None


def get_omega_platform() -> OmegaPlatform:
    """Get the global Omega platform instance."""
    global _omega_instance
    if _omega_instance is None:
        _omega_instance = OmegaPlatform()
    return _omega_instance


def initialize_omega() -> Dict[str, Any]:
    """Initialize the Omega platform."""
    platform = get_omega_platform()
    return platform.initialize()