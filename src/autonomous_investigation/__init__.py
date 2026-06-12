"""
Autonomous Fraud Investigation & Decision Intelligence Platform.

Provides AI-powered investigation automation, decision intelligence,
case prioritization, and analyst copilot capabilities.

Core Components:
- Investigation Engine: Automated fraud investigation orchestration
- Evidence Collection Engine: Multi-source evidence gathering
- Decision Intelligence Engine: Risk-based recommendations
- Case Prioritization Engine: AI-driven case prioritization
- Fraud Narrative Generator: Automated report generation
- Analyst Copilot Service: AI assistant for fraud analysts

Usage:
    from src.autonomous_investigation import get_investigation_service

    service = get_investigation_service()
    investigation = await service.create_investigation(alert_id)
    result = await service.analyze_investigation(investigation.id)
"""

from .models import (
    # Enums
    InvestigationStatus,
    EvidenceType,
    RiskLevel,
    DecisionType,
    CasePriority,
    SeverityLevel,
    # Core Models
    InvestigationCase,
    EvidenceArtifact,
    RiskAssessment,
    DecisionRecommendation,
    FraudNarrative,
    CasePriority as CasePriorityModel,
    InvestigationTimeline,
    AnalystRecommendation,
    AuditRecord,
    EntityCorrelation,
    FraudPattern,
    ActionPlan,
    CaseMetrics,
)

from .store import (
    InvestigationStore,
    get_investigation_store,
    reset_store,
)

from .investigation_engine import (
    InvestigationEngine,
    get_investigation_engine,
)

from .evidence_collector import (
    EvidenceCollector,
    get_evidence_collector,
)

from .decision_engine import (
    DecisionIntelligenceEngine,
    get_decision_engine,
)

from .case_prioritization import (
    CasePrioritizationEngine,
    get_case_prioritization_engine,
)

from .report_generator import (
    FraudNarrativeGenerator,
    get_report_generator,
)

from .recommendation_engine import (
    RecommendationEngine,
    get_recommendation_engine,
)

from .explainability import (
    ExplainabilityEngine,
    get_explainability_engine,
)

from .service import (
    InvestigationService,
    InvestigationConfig,
    get_investigation_service,
)

__all__ = [
    # Enums
    "InvestigationStatus",
    "EvidenceType",
    "RiskLevel",
    "DecisionType",
    "CasePriority",
    "SeverityLevel",
    # Core Models
    "InvestigationCase",
    "EvidenceArtifact",
    "RiskAssessment",
    "DecisionRecommendation",
    "FraudNarrative",
    "CasePriorityModel",
    "InvestigationTimeline",
    "AnalystRecommendation",
    "AuditRecord",
    "EntityCorrelation",
    "FraudPattern",
    "ActionPlan",
    "CaseMetrics",
    # Storage
    "InvestigationStore",
    "get_investigation_store",
    "reset_store",
    # Engines
    "InvestigationEngine",
    "get_investigation_engine",
    "EvidenceCollector",
    "get_evidence_collector",
    "DecisionIntelligenceEngine",
    "get_decision_engine",
    "CasePrioritizationEngine",
    "get_case_prioritization_engine",
    "FraudNarrativeGenerator",
    "get_report_generator",
    "RecommendationEngine",
    "get_recommendation_engine",
    "ExplainabilityEngine",
    "get_explainability_engine",
    # Service
    "InvestigationService",
    "InvestigationConfig",
    "get_investigation_service",
]