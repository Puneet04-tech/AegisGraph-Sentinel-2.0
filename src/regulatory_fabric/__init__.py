"""
Regulatory Intelligence & Compliance Fabric Module for AegisGraph Sentinel 2.0

Production-grade autonomous compliance ecosystem capable of:
- Automatically monitoring regulatory requirements
- Mapping controls to regulatory requirements
- Detecting compliance drift in real-time
- Collecting and managing audit evidence
- Automating audit preparation and execution
- Validating control effectiveness
- Assessing and managing compliance risks
- Tracking regulatory changes
- Maintaining compliance knowledge graph
- Generating executive compliance dashboards

Exports:
    Models:
        Regulation, Control, Policy, ComplianceAssessment, AuditEvidence
        ComplianceRisk, ControlMapping, RegulatoryUpdate, ComplianceDashboard
        RegulationDomain, ControlStatus, AssessmentStatus, RiskLevel
    
    Services:
        ComplianceStore - Central storage for compliance data
        RegulationIntelligenceEngine - Regulatory monitoring and analysis
        ComplianceDriftDetector - Real-time drift detection
        PolicyMappingEngine - Control-requirement mapping
        EvidenceCollector - Automated evidence collection
        AuditAutomationEngine - Audit planning and execution
        ControlValidationService - Control effectiveness validation
        ComplianceRiskEngine - Risk assessment
        RegulatoryChangeTracker - Change tracking
        ComplianceKnowledgeGraph - Relationship graph
        ComplianceDashboardService - Executive dashboard

Usage:
    from src.regulatory_fabric import (
        get_compliance_store,
        get_intelligence_engine,
        get_dashboard_service,
    )
    
    store = get_compliance_store()
    engine = get_intelligence_engine()
    dashboard = get_dashboard_service()
"""

from .models import (
    # Enums
    RegulationDomain,
    RegulationStatus,
    ControlStatus,
    ControlEffectiveness,
    AssessmentStatus,
    EvidenceStatus,
    RiskLevel,
    # Models
    Regulation,
    Control,
    Policy,
    ControlMapping,
    ComplianceAssessment,
    AuditEvidence,
    ComplianceRisk,
    RegulatoryUpdate,
    ComplianceDashboard,
)
from .store import ComplianceStore, get_compliance_store
from .intelligence_engine import (
    RegulationIntelligenceEngine,
    IntelligenceConfig,
    IntelligenceAlert,
    get_intelligence_engine,
)
from .drift_detector import (
    ComplianceDriftDetector,
    DriftEvent,
    BaselineSnapshot,
    get_drift_detector,
)
from .policy_mapper import PolicyMappingEngine, MappingSuggestion, get_policy_mapper
from .evidence_collector import EvidenceCollector, EvidenceCollectionJob, get_evidence_collector
from .audit_engine import (
    AuditAutomationEngine,
    AuditPlan,
    AuditFinding,
    get_audit_engine,
)
from .control_validator import (
    ControlValidationService,
    ValidationResult,
    get_control_validator,
)
from .risk_engine import ComplianceRiskEngine, RiskCalculation, get_risk_engine
from .change_tracker import (
    RegulatoryChangeTracker,
    ChangeAlert,
    get_change_tracker,
)
from .knowledge_graph import (
    ComplianceKnowledgeGraph,
    GraphNode,
    GraphEdge,
    get_knowledge_graph,
)
from .dashboard import ComplianceDashboardService, get_dashboard_service


__all__ = [
    # Enums
    "RegulationDomain",
    "RegulationStatus",
    "ControlStatus",
    "ControlEffectiveness",
    "AssessmentStatus",
    "EvidenceStatus",
    "RiskLevel",
    # Models
    "Regulation",
    "Control",
    "Policy",
    "ControlMapping",
    "ComplianceAssessment",
    "AuditEvidence",
    "ComplianceRisk",
    "RegulatoryUpdate",
    "ComplianceDashboard",
    # Store
    "ComplianceStore",
    "get_compliance_store",
    # Intelligence
    "RegulationIntelligenceEngine",
    "IntelligenceConfig",
    "IntelligenceAlert",
    "get_intelligence_engine",
    # Drift Detection
    "ComplianceDriftDetector",
    "DriftEvent",
    "BaselineSnapshot",
    "get_drift_detector",
    # Policy Mapping
    "PolicyMappingEngine",
    "MappingSuggestion",
    "get_policy_mapper",
    # Evidence Collection
    "EvidenceCollector",
    "EvidenceCollectionJob",
    "get_evidence_collector",
    # Audit Automation
    "AuditAutomationEngine",
    "AuditPlan",
    "AuditFinding",
    "get_audit_engine",
    # Control Validation
    "ControlValidationService",
    "ValidationResult",
    "get_control_validator",
    # Risk Engine
    "ComplianceRiskEngine",
    "RiskCalculation",
    "get_risk_engine",
    # Change Tracking
    "RegulatoryChangeTracker",
    "ChangeAlert",
    "get_change_tracker",
    # Knowledge Graph
    "ComplianceKnowledgeGraph",
    "GraphNode",
    "GraphEdge",
    "get_knowledge_graph",
    # Dashboard
    "ComplianceDashboardService",
    "get_dashboard_service",
]