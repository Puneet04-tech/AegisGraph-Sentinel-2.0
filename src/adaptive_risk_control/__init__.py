"""
Autonomous Fraud Prevention & Adaptive Risk Control Platform.

Provides real-time fraud prevention, dynamic risk controls,
adaptive security policies, and AI-driven risk intelligence.

Core Components:
- Adaptive Risk Engine: Continuous risk evaluation
- Fraud Prevention Engine: Real-time fraud blocking
- Policy Decision Engine: AI-driven policy enforcement
- Dynamic Control Manager: Adaptive security controls
- Real-Time Mitigation Engine: Immediate threat response

Usage:
    from src.adaptive_risk_control import get_prevention_service

    service = get_prevention_service()
    assessment = await service.evaluate_transaction(transaction_data)
    if assessment.risk_level.value == "critical":
        await service.prevent_fraud(assessment)
"""

from .models import (
    # Enums
    RiskLevel,
    DecisionType,
    ControlStatus,
    MitigationAction,
    LearningFeedbackType,
    # Core Models
    RiskProfile,
    RiskDecision,
    FraudAttempt,
    AdaptivePolicy,
    ControlRule,
    MitigationAction as MitigationActionModel,
    TransactionAssessment,
    RiskRecommendation,
    LearningFeedback,
    AuditRecord,
    PolicyChange,
    ThreatIndicator,
)

from .store import (
    AdaptiveRiskStore,
    get_adaptive_risk_store,
    reset_store,
)

from .risk_engine import (
    AdaptiveRiskEngine,
    get_risk_engine,
)

from .prevention_engine import (
    FraudPreventionEngine,
    get_prevention_engine,
)

from .policy_engine import (
    PolicyDecisionEngine,
    get_policy_engine,
)

from .control_manager import (
    DynamicControlManager,
    get_control_manager,
)

from .mitigation_engine import (
    RealTimeMitigationEngine,
    get_mitigation_engine,
)

from .recommendation_engine import (
    PolicyRecommendationEngine,
    get_recommendation_engine,
)

from .adaptive_learning import (
    AdaptiveLearningEngine,
    get_learning_engine,
)

from .service import (
    AdaptiveRiskControlService,
    AdaptiveRiskConfig,
    get_prevention_service,
)

__all__ = [
    # Enums
    "RiskLevel",
    "DecisionType",
    "ControlStatus",
    "MitigationAction",
    "LearningFeedbackType",
    # Core Models
    "RiskProfile",
    "RiskDecision",
    "FraudAttempt",
    "AdaptivePolicy",
    "ControlRule",
    "MitigationActionModel",
    "TransactionAssessment",
    "RiskRecommendation",
    "LearningFeedback",
    "AuditRecord",
    "PolicyChange",
    "ThreatIndicator",
    # Storage
    "AdaptiveRiskStore",
    "get_adaptive_risk_store",
    "reset_store",
    # Engines
    "AdaptiveRiskEngine",
    "get_risk_engine",
    "FraudPreventionEngine",
    "get_prevention_engine",
    "PolicyDecisionEngine",
    "get_policy_engine",
    "DynamicControlManager",
    "get_control_manager",
    "RealTimeMitigationEngine",
    "get_mitigation_engine",
    "PolicyRecommendationEngine",
    "get_recommendation_engine",
    "AdaptiveLearningEngine",
    "get_learning_engine",
    # Service
    "AdaptiveRiskControlService",
    "AdaptiveRiskConfig",
    "get_prevention_service",
]