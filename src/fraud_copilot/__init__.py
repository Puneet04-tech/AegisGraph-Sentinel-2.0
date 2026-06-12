"""
Fraud Analyst Copilot.

AI-powered fraud analyst copilot for investigation assistance,
semantic search, intelligence discovery, and decision support.
"""

from .models import (
    # Enums
    InsightType,
    MessageRole,
    RecommendationType,
    # Data Classes
    AuditEvent,
    CaseSummary,
    ConversationMessage,
    CopilotSession,
    DecisionSupport,
    GeneratedReport,
    InvestigationInsight,
    KnowledgeDocument,
    Recommendation,
    ReportSection,
    ThreatExplanation,
)

from .store import (
    FraudCopilotStore,
    get_copilot_store,
    reset_copilot_store,
)

from .copilot_engine import (
    CopilotEngine,
    get_copilot_engine,
    reset_copilot_engine,
)

from .search_engine import (
    SearchEngine,
    get_search_engine,
    reset_search_engine,
)

from .recommendation_engine import (
    RecommendationEngine,
    get_recommendation_engine,
    reset_recommendation_engine,
)

from .service import (
    FraudCopilotService,
    get_fraud_copilot_service,
    reset_fraud_copilot_service,
)

__all__ = [
    # Enums
    "InsightType",
    "MessageRole",
    "RecommendationType",
    # Models
    "AuditEvent",
    "CaseSummary",
    "ConversationMessage",
    "CopilotSession",
    "DecisionSupport",
    "GeneratedReport",
    "InvestigationInsight",
    "KnowledgeDocument",
    "Recommendation",
    "ReportSection",
    "ThreatExplanation",
    # Store
    "FraudCopilotStore",
    "get_copilot_store",
    "reset_copilot_store",
    # Engine
    "CopilotEngine",
    "get_copilot_engine",
    "reset_copilot_engine",
    # Search
    "SearchEngine",
    "get_search_engine",
    "reset_search_engine",
    # Recommendations
    "RecommendationEngine",
    "get_recommendation_engine",
    "reset_recommendation_engine",
    # Service
    "FraudCopilotService",
    "get_fraud_copilot_service",
    "reset_fraud_copilot_service",
]