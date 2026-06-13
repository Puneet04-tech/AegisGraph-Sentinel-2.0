"""
Global Fraud Intelligence Knowledge Graph & Federation Platform.

Provides cross-organization fraud intelligence sharing, knowledge graph-based
investigations, federated threat intelligence exchange, and network analysis
for large-scale fraud detection.

Core Components:
- Federation Engine: Cross-organization intelligence sharing
- Knowledge Graph: Entity relationships and graph traversal
- Entity Correlation: Cross-institution entity matching
- Threat Exchange: Federated threat intelligence
- Campaign Discovery: Multi-institution fraud campaign detection
- Network Analysis: Graph-based fraud network discovery

Usage:
    from src.global_intelligence import get_global_intelligence_service

    service = get_global_intelligence_service()

    # Share intelligence
    await service.share_intelligence(indicator)

    # Search federated sources
    results = await service.federated_search(query)

    # Discover fraud networks
    networks = await service.discover_fraud_networks(entity_id)
"""

from .models import (
    # Enums
    EntityType,
    ThreatLevel,
    IntelligenceSource,
    InvestigationStatus,
    FederationStatus,
    NetworkType,
    CorrelationStrength,
    # Core Models
    FederatedEntity,
    FraudNetwork,
    ThreatIndicator,
    FraudCampaign,
    InvestigationCase,
    KnowledgeGraphNode,
    KnowledgeGraphEdge,
    RiskPropagation,
    ThreatCorrelation,
    FederationPartner,
    AuditRecord,
    IntelligenceQuery,
    IntelligenceShare,
    GraphQuery,
    NetworkAnalysisResult,
    InvestigationReport,
    DashboardMetrics,
    SharingPolicy,
)

from .store import (
    GlobalIntelligenceStore,
    get_global_intelligence_store,
    reset_store,
)

from .federation_engine import (
    FederationEngine,
    get_federation_engine,
    reset_engine,
)

from .knowledge_graph import (
    KnowledgeGraphEngine,
    get_knowledge_graph_engine,
    GraphTraversalResult,
    PatternMatch,
)

from .entity_correlation import (
    EntityCorrelationEngine,
    get_entity_correlation_engine,
    CorrelationResult,
    EntityMatch,
)

from .threat_exchange import (
    ThreatIntelligenceExchange,
    get_threat_exchange,
    ThreatIndicatorSync,
)

from .campaign_discovery import (
    CampaignDiscoveryEngine,
    get_campaign_discovery_engine,
    CampaignAnalysis,
)

from .network_analysis import (
    NetworkAnalysisEngine,
    get_network_analysis_engine,
    CommunityDetection,
    CentralityMetrics,
)

from .federated_search import (
    FederatedSearchEngine,
    get_federated_search_engine,
    SearchResult,
)

from .risk_propagation import (
    RiskPropagationEngine,
    get_risk_propagation_engine,
    PropagationPath,
)

from .audit import (
    GlobalIntelligenceAudit,
    get_audit_service,
    AuditQuery,
)

from .service import (
    GlobalIntelligenceService,
    GlobalIntelligenceConfig,
    get_global_intelligence_service,
    reset_service,
)

__all__ = [
    # Enums
    "EntityType",
    "ThreatLevel",
    "IntelligenceSource",
    "InvestigationStatus",
    "FederationStatus",
    "NetworkType",
    "CorrelationStrength",
    # Core Models
    "FederatedEntity",
    "FraudNetwork",
    "ThreatIndicator",
    "FraudCampaign",
    "InvestigationCase",
    "KnowledgeGraphNode",
    "KnowledgeGraphEdge",
    "RiskPropagation",
    "ThreatCorrelation",
    "FederationPartner",
    "AuditRecord",
    "IntelligenceQuery",
    "IntelligenceShare",
    "GraphQuery",
    "NetworkAnalysisResult",
    "InvestigationReport",
    "DashboardMetrics",
    "SharingPolicy",
    # Storage
    "GlobalIntelligenceStore",
    "get_global_intelligence_store",
    "reset_store",
    # Federation Engine
    "FederationEngine",
    "get_federation_engine",
    "reset_engine",
    # Knowledge Graph
    "KnowledgeGraphEngine",
    "get_knowledge_graph_engine",
    "GraphTraversalResult",
    "PatternMatch",
    # Entity Correlation
    "EntityCorrelationEngine",
    "get_entity_correlation_engine",
    "CorrelationResult",
    "EntityMatch",
    # Threat Exchange
    "ThreatIntelligenceExchange",
    "get_threat_exchange",
    "ThreatIndicatorSync",
    # Campaign Discovery
    "CampaignDiscoveryEngine",
    "get_campaign_discovery_engine",
    "CampaignAnalysis",
    # Network Analysis
    "NetworkAnalysisEngine",
    "get_network_analysis_engine",
    "CommunityDetection",
    "CentralityMetrics",
    # Federated Search
    "FederatedSearchEngine",
    "get_federated_search_engine",
    "SearchResult",
    # Risk Propagation
    "RiskPropagationEngine",
    "get_risk_propagation_engine",
    "PropagationPath",
    # Audit
    "GlobalIntelligenceAudit",
    "get_audit_service",
    "AuditQuery",
    # Main Service
    "GlobalIntelligenceService",
    "GlobalIntelligenceConfig",
    "get_global_intelligence_service",
    "reset_service",
]