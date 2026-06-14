"""
Cyber-Fraud Warfare Intelligence Platform Module for AegisGraph Sentinel 2.0

Production-grade strategic intelligence platform for analyzing:
- Nation-state attacks and advanced persistent threats
- Organized cybercrime operations
- Fraud ecosystems and campaigns
- Coordinated attack campaigns
- Threat actor capabilities and intentions

Exports:
    Models:
        ThreatActor, Campaign, Attribution, ThreatProfile
        AttackPattern, RiskAssessment, ThreatRelationship
        ThreatActorType, ThreatActorSponsor, CampaignStatus
    
    Stores:
        WarfareStore - Central storage for warfare data
    
    Engines:
        ThreatActorIntelligenceEngine - Actor analysis and tracking
        CampaignAttributionEngine - Campaign attribution
        StrategicThreatDashboard - Executive threat visibility
        ThreatKnowledgeGraph - Relationship graph

Usage:
    from src.cyber_fraud_warfare import (
        get_warfare_store,
        get_threat_actor_engine,
        get_strategic_dashboard,
    )
    
    store = get_warfare_store()
    engine = get_threat_actor_engine()
    dashboard = get_strategic_dashboard()
"""

from .models import (
    # Enums
    ThreatActorType,
    ThreatActorSponsor,
    CampaignStatus,
    AttributionConfidence,
    RiskSeverity,
    # Models
    ThreatActor,
    Campaign,
    Attribution,
    ThreatProfile,
    AttackPattern,
    RiskAssessment,
    ThreatRelationship,
)
from .store import WarfareStore, get_warfare_store
from .threat_actor_engine import (
    ThreatActorIntelligenceEngine,
    ActorAnalysis,
    get_threat_actor_engine,
)
from .attribution_engine import (
    CampaignAttributionEngine,
    AttributionResult,
    get_attribution_engine,
)
from .dashboard import (
    StrategicThreatDashboard,
    get_strategic_dashboard,
)
from .knowledge_graph import (
    ThreatKnowledgeGraph,
    GraphNode,
    GraphEdge,
    get_threat_knowledge_graph,
)


__all__ = [
    # Enums
    "ThreatActorType",
    "ThreatActorSponsor",
    "CampaignStatus",
    "AttributionConfidence",
    "RiskSeverity",
    # Models
    "ThreatActor",
    "Campaign",
    "Attribution",
    "ThreatProfile",
    "AttackPattern",
    "RiskAssessment",
    "ThreatRelationship",
    # Store
    "WarfareStore",
    "get_warfare_store",
    # Engines
    "ThreatActorIntelligenceEngine",
    "ActorAnalysis",
    "get_threat_actor_engine",
    "CampaignAttributionEngine",
    "AttributionResult",
    "get_attribution_engine",
    # Dashboard
    "StrategicThreatDashboard",
    "get_strategic_dashboard",
    # Knowledge Graph
    "ThreatKnowledgeGraph",
    "GraphNode",
    "GraphEdge",
    "get_threat_knowledge_graph",
]