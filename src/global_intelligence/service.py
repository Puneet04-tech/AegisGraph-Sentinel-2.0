"""
Main Service for Global Fraud Intelligence Knowledge Graph & Federation Platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    DashboardMetrics,
    EntityType,
    FederatedEntity,
    FederationPartner,
    FraudCampaign,
    FraudNetwork,
    InvestigationCase,
    InvestigationStatus,
    IntelligenceSource,
    ThreatIndicator,
    ThreatLevel,
)
from .store import GlobalIntelligenceStore, get_global_intelligence_store
from .federation_engine import FederationEngine, get_federation_engine
from .knowledge_graph import KnowledgeGraphEngine, get_knowledge_graph_engine
from .entity_correlation import EntityCorrelationEngine, get_entity_correlation_engine
from .threat_exchange import ThreatIntelligenceExchange, get_threat_exchange
from .campaign_discovery import CampaignDiscoveryEngine, get_campaign_discovery_engine
from .network_analysis import NetworkAnalysisEngine, get_network_analysis_engine
from .federated_search import FederatedSearchEngine, get_federated_search_engine
from .risk_propagation import RiskPropagationEngine, get_risk_propagation_engine
from .audit import GlobalIntelligenceAudit, get_audit_service


@dataclass
class GlobalIntelligenceConfig:
    """Configuration for global intelligence service."""
    federation_id: str = "primary"
    enable_auto_discovery: bool = True
    discovery_interval_seconds: int = 3600
    cache_ttl_seconds: int = 300
    max_results_per_query: int = 100


class GlobalIntelligenceService:
    """
    Main orchestrator for global fraud intelligence operations.

    Integrates all components:
    - Federation Engine
    - Knowledge Graph
    - Entity Correlation
    - Threat Exchange
    - Campaign Discovery
    - Network Analysis
    - Federated Search
    - Risk Propagation
    - Audit Service
    """

    def __init__(
        self,
        store: Optional[GlobalIntelligenceStore] = None,
        config: Optional[GlobalIntelligenceConfig] = None,
    ):
        self._store = store or get_global_intelligence_store()
        self._config = config or GlobalIntelligenceConfig()

        # Initialize all engines
        self._federation = get_federation_engine()
        self._knowledge_graph = get_knowledge_graph_engine()
        self._correlation = get_entity_correlation_engine()
        self._threat_exchange = get_threat_exchange()
        self._campaign_discovery = get_campaign_discovery_engine()
        self._network_analysis = get_network_analysis_engine()
        self._federated_search = get_federated_search_engine()
        self._risk_propagation = get_risk_propagation_engine()
        self._audit = get_audit_service()

    # Dashboard
    def get_dashboard_metrics(self) -> DashboardMetrics:
        """Get dashboard metrics for global intelligence."""
        stats = self._store.get_stats()
        threat_dist = stats.get("threat_distribution", {})

        return DashboardMetrics(
            total_entities=stats["total_entities"],
            active_threats=sum(1 for e in self._store._entities.values()
                            if e.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)),
            federation_partners=stats["active_partners"],
            campaigns_active=stats["active_campaigns"],
            networks_discovered=stats["total_networks"],
            investigations_open=stats["open_investigations"],
            indicators_shared=stats["active_indicators"],
            indicators_received=0,
            avg_risk_score=(
                sum(e.risk_score for e in self._store._entities.values()) / stats["total_entities"]
                if stats["total_entities"] > 0 else 0
            ),
            threat_distribution=threat_dist,
            last_updated=datetime.now(timezone.utc),
        )

    # Intelligence Sharing
    def share_intelligence(
        self,
        entity: FederatedEntity,
        target_partners: List[str],
        user_id: str = "system",
    ) -> Dict[str, Any]:
        """Share intelligence with partners."""
        result = self._federation.share_intelligence(entity, target_partners, user_id=user_id)

        self._audit.log_operation(
            operation="intelligence_share",
            user_id=user_id,
            partner_id=entity.partner_id,
            entity_ids=[entity.entity_id],
            success=result.success,
        )

        return {
            "success": result.success,
            "share_id": result.share_id,
            "message": result.message,
        }

    def receive_intelligence(
        self,
        partner_id: str,
        entities: List[FederatedEntity],
    ) -> int:
        """Receive intelligence from a partner."""
        count = 0
        for entity in entities:
            self._store.store_entity(entity)
            count += 1

        self._audit.log_operation(
            operation="intelligence_receive",
            user_id="system",
            partner_id=partner_id,
            entity_ids=[e.entity_id for e in entities],
            success=True,
        )

        return count

    # Search
    def search_intelligence(
        self,
        query: str,
        entity_types: Optional[List[str]] = None,
        threat_levels: Optional[List[str]] = None,
        include_internal: bool = True,
        include_federation: bool = True,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Search across all intelligence sources."""
        from .federated_search import SearchQuery as FedSearchQuery

        # Build search query
        entity_type_enums = [EntityType(t) for t in (entity_types or []) if t]
        threat_level_enums = [ThreatLevel(t) for t in (threat_levels or []) if t]

        search_query = FedSearchQuery(
            query_id=str(uuid.uuid4()),
            query_text=query,
            entity_types=entity_type_enums,
            threat_levels=threat_level_enums,
            date_range_start=None,
            date_range_end=None,
            include_internal=include_internal,
            include_federation=include_federation,
            max_results_per_source=limit,
            fuzzy_match=True,
        )

        results = self._federated_search.search(search_query)

        return [
            {
                "result_id": r.result_id,
                "entity_id": r.entity.entity_id,
                "entity_type": r.entity.entity_type.value,
                "threat_level": r.entity.threat_level.value,
                "risk_score": r.entity.risk_score,
                "source": r.source.value,
                "partner_id": r.partner_id,
                "relevance_score": r.relevance_score,
                "matched_fields": r.matched_fields,
            }
            for r in results
        ]

    # Entity Correlation
    def correlate_entities(
        self,
        entity_id: str,
    ) -> Dict[str, Any]:
        """Correlate an entity with others."""
        entity = self._store.get_entity(entity_id)
        if not entity:
            return {"error": "Entity not found"}

        result = self._correlation.correlate_entities(entity)

        return {
            "primary_entity_id": result.primary_entity_id,
            "total_candidates": result.total_candidates,
            "matches_found": result.matches_found,
            "matches": [
                {
                    "match_id": m.match_id,
                    "entity_2_id": m.entity_2_id,
                    "correlation_score": m.correlation_score,
                    "strength": m.strength.value,
                    "match_type": m.match_type,
                    "shared_attributes": m.shared_attributes,
                }
                for m in result.matches
            ],
            "avg_score": result.avg_score,
        }

    # Network Discovery
    def discover_networks(
        self,
        seed_entity_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Discover fraud networks."""
        networks = self._network_analysis.discover_networks(seed_entity_id)

        return [
            {
                "network_id": n.network_id,
                "network_type": n.network_type.value,
                "member_count": n.member_count,
                "threat_level": n.threat_level.value,
                "confidence_score": n.confidence_score,
                "activity_score": n.activity_score,
                "first_detected": n.first_detected.isoformat(),
            }
            for n in networks
        ]

    def analyze_network(
        self,
        network_id: str,
    ) -> Dict[str, Any]:
        """Analyze a fraud network in detail."""
        return self._network_analysis.analyze_network(network_id)

    # Campaign Discovery
    def discover_campaigns(
        self,
        entity_ids: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Discover fraud campaigns."""
        campaigns = self._campaign_discovery.discover_campaigns(entity_ids)

        return [
            {
                "campaign_id": c.campaign_id,
                "campaign_name": c.campaign_name,
                "threat_type": c.threat_type,
                "threat_level": c.threat_level.value,
                "victim_count": c.victim_count,
                "total_loss": c.total_loss,
                "affected_institutions": len(c.affected_institutions),
                "status": c.status,
            }
            for c in campaigns
        ]

    def analyze_campaign(
        self,
        campaign_id: str,
    ) -> Dict[str, Any]:
        """Analyze a fraud campaign."""
        analysis = self._campaign_discovery.analyze_campaign(campaign_id)

        return {
            "campaign_id": analysis.campaign_id,
            "analysis_type": analysis.analysis_type,
            "findings": analysis.findings,
            "statistics": analysis.statistics,
            "recommended_actions": analysis.recommended_actions,
            "confidence_score": analysis.confidence_score,
        }

    # Risk Propagation
    def propagate_risk(
        self,
        entity_id: str,
    ) -> Dict[str, Any]:
        """Propagate risk from an entity."""
        propagations = self._risk_propagation.propagate_risk(entity_id)

        return {
            "source_entity_id": entity_id,
            "propagation_count": len(propagations),
            "propagations": [
                {
                    "target_id": p.target_entity_id,
                    "risk_score": p.risk_score,
                    "hop_count": p.hop_count,
                    "risk_factors": p.risk_factors,
                }
                for p in propagations[:20]
            ],
        }

    def get_risk_trajectory(
        self,
        entity_id: str,
    ) -> Dict[str, Any]:
        """Get risk trajectory for an entity."""
        return self._risk_propagation.get_risk_trajectory(entity_id)

    # Graph Operations
    def get_entity_graph(
        self,
        entity_id: str,
        depth: int = 2,
    ) -> Dict[str, Any]:
        """Get graph view centered on an entity."""
        snapshot = self._store.get_graph_snapshot(entity_id, depth)

        return {
            "center": snapshot["center"],
            "depth": snapshot["depth"],
            "nodes": [
                {
                    "node_id": n.node_id,
                    "entity_type": n.entity_type.value,
                    "properties": n.properties,
                    "risk_score": n.risk_score,
                }
                for n in snapshot["nodes"]
                if n
            ],
            "edges": [
                {
                    "edge_id": e.edge_id,
                    "source": e.source_id,
                    "target": e.target_id,
                    "relationship_type": e.relationship_type,
                    "weight": e.weight,
                }
                for e in snapshot["edges"]
            ],
        }

    # Partner Management
    def register_partner(
        self,
        organization_name: str,
        organization_type: str,
        api_endpoint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a new federation partner."""
        partner = self._federation.register_partner(
            organization_name=organization_name,
            organization_type=organization_type,
            api_endpoint=api_endpoint,
        )

        return {
            "partner_id": partner.partner_id,
            "organization_name": partner.organization_name,
            "status": partner.status.value,
        }

    def get_partners(self) -> List[Dict[str, Any]]:
        """Get all federation partners."""
        partners = self._store.get_all_partners()

        return [
            {
                "partner_id": p.partner_id,
                "organization_name": p.organization_name,
                "status": p.status.value,
                "trust_level": p.trust_level,
                "shared_entities": p.shared_entities,
                "received_intelligence": p.received_intelligence,
                "joined_at": p.joined_at.isoformat(),
            }
            for p in partners
        ]

    # Investigation Management
    def create_investigation(
        self,
        title: str,
        description: str,
        priority: int,
        created_by: str,
        entity_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a new investigation case."""
        investigation = InvestigationCase(
            case_id=str(uuid.uuid4()),
            title=title,
            description=description,
            status=InvestigationStatus.OPEN,
            priority=priority,
            created_by=created_by,
            assigned_to=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            closed_at=None,
            entities=entity_ids or [],
        )

        self._store.store_investigation(investigation)

        self._audit.log_operation(
            operation="investigation_create",
            user_id=created_by,
            entity_ids=entity_ids or [],
            metadata={"case_id": investigation.case_id},
        )

        return {
            "case_id": investigation.case_id,
            "title": investigation.title,
            "status": investigation.status.value,
        }

    def get_investigations(
        self,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get investigation cases."""
        if status:
            status_enum = InvestigationStatus(status)
            investigations = self._store.get_investigations_by_status(status_enum, limit)
        else:
            investigations = self._store.get_all_investigations(limit)

        return [
            {
                "case_id": i.case_id,
                "title": i.title,
                "status": i.status.value,
                "priority": i.priority,
                "created_by": i.created_by,
                "created_at": i.created_at.isoformat(),
                "entity_count": len(i.entities),
            }
            for i in investigations
        ]

    # Threat Indicators
    def add_threat_indicator(
        self,
        indicator_type: str,
        value: str,
        threat_type: str,
        threat_level: str,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add a threat indicator."""
        indicator = self._threat_exchange.add_indicator(
            indicator_type=indicator_type,
            value=value,
            threat_type=threat_type,
            threat_level=ThreatLevel(threat_level),
            source=IntelligenceSource.INTERNAL,
            tags=tags,
        )

        return {
            "indicator_id": indicator.indicator_id,
            "indicator_type": indicator.indicator_type,
            "threat_level": indicator.threat_level.value,
        }

    def search_indicators(
        self,
        query: Optional[str] = None,
        threat_level: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Search threat indicators."""
        level = ThreatLevel(threat_level) if threat_level else None
        indicators = self._threat_exchange.search_indicators(
            query=query,
            threat_level=level,
            limit=limit,
        )

        return [
            {
                "indicator_id": i.indicator_id,
                "indicator_type": i.indicator_type,
                "value": i.value,
                "threat_type": i.threat_type,
                "threat_level": i.threat_level.value,
                "confidence": i.confidence,
                "last_seen": i.last_seen.isoformat(),
            }
            for i in indicators
        ]


# Global service instance
_service: Optional[GlobalIntelligenceService] = None


def get_global_intelligence_service() -> GlobalIntelligenceService:
    """Get the global intelligence service instance."""
    global _service
    if _service is None:
        _service = GlobalIntelligenceService()
    return _service


def reset_service() -> None:
    """Reset the service (for testing)."""
    global _service
    _service = None