"""
Storage layer for Global Fraud Intelligence Knowledge Graph & Federation Platform.
"""

from __future__ import annotations

import threading
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set
import uuid

from .models import (
    EntityType,
    FederatedEntity,
    FraudNetwork,
    ThreatIndicator,
    FraudCampaign,
    InvestigationCase,
    KnowledgeGraphNode,
    KnowledgeGraphEdge,
    FederationPartner,
    AuditRecord,
    InvestigationStatus,
    FederationStatus,
    ThreatLevel,
)


class LRUCache(OrderedDict):
    """Thread-safe LRU cache with configurable max size."""

    def __init__(self, maxsize: int = 10000, *args, **kwds):
        self.maxsize = maxsize
        super().__init__(*args, **kwds)
        self._lock = threading.RLock()

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            value = super().__getitem__(key)
            self.move_to_end(key)
            return value

    def __setitem__(self, key: str, value: Any) -> None:
        with self._lock:
            if key in self:
                self.move_to_end(key)
            super().__setitem__(key, value)
            if len(self) > self.maxsize:
                oldest = next(iter(self))
                del self[oldest]

    def __delitem__(self, key: str) -> None:
        with self._lock:
            super().__delitem__(key)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return super().__contains__(key)

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            try:
                return self[key]
            except KeyError:
                return default

    def pop(self, key: str, *args) -> Any:
        with self._lock:
            return super().pop(key, *args)

    def clear(self) -> None:
        with self._lock:
            super().clear()


class GlobalIntelligenceStore:
    """
    Central storage for global fraud intelligence data.

    Provides O(1) entity retrieval and thread-safe operations.
    """

    def __init__(
        self,
        max_entities: int = 100000,
        max_indicators: int = 500000,
        max_networks: int = 10000,
    ):
        # Core storage
        self._entities: LRUCache = LRUCache(maxsize=max_entities)
        self._indicators: LRUCache = LRUCache(maxsize=max_indicators)
        self._networks: LRUCache = LRUCache(maxsize=max_networks)
        self._campaigns: Dict[str, FraudCampaign] = {}
        self._investigations: Dict[str, InvestigationCase] = {}
        self._partners: Dict[str, FederationPartner] = {}
        self._audit_records: List[AuditRecord] = []
        self._graph_nodes: Dict[str, KnowledgeGraphNode] = {}
        self._graph_edges: Dict[str, KnowledgeGraphEdge] = {}

        # Index structures for fast lookup
        self._entity_index: Dict[EntityType, Dict[str, str]] = defaultdict(dict)
        self._indicator_index: Dict[str, List[str]] = defaultdict(list)
        self._partner_entities: Dict[str, Set[str]] = defaultdict(set)
        self._network_members: Dict[str, Set[str]] = defaultdict(set)

        self._lock = threading.RLock()

        # Initialize default partners (self as primary)
        self._initialize_defaults()

    def _initialize_defaults(self) -> None:
        """Initialize with default configuration."""
        self_partner = FederationPartner(
            partner_id="self",
            organization_name="Self Organization",
            organization_type="internal",
            status=FederationStatus.ACTIVE,
            trust_level=100,
            api_endpoint=None,
            api_key_hash=None,
            joined_at=datetime.now(timezone.utc),
            last_sync=datetime.now(timezone.utc),
            sharing_policy={"allow_all": True},
        )
        self._partners["self"] = self_partner

    # Entity Management
    def store_entity(self, entity: FederatedEntity) -> None:
        """Store a federated entity."""
        with self._lock:
            self._entities[entity.entity_id] = entity
            self._entity_index[entity.entity_type][entity.entity_id] = entity.entity_id
            self._partner_entities[entity.partner_id].add(entity.entity_id)

    def get_entity(self, entity_id: str) -> Optional[FederatedEntity]:
        """Get entity by ID with O(1) lookup."""
        return self._entities.get(entity_id)

    def get_entities_by_type(
        self, entity_type: EntityType, limit: int = 100
    ) -> List[FederatedEntity]:
        """Get entities by type."""
        entity_ids = list(self._entity_index.get(entity_type, {}).values())[:limit]
        return [self._entities[eid] for eid in entity_ids if eid in self._entities]

    def get_entities_by_partner(
        self, partner_id: str, limit: int = 100
    ) -> List[FederatedEntity]:
        """Get entities shared by a partner."""
        entity_ids = list(self._partner_entities.get(partner_id, set()))[:limit]
        return [self._entities[eid] for eid in entity_ids if eid in self._entities]

    def get_entities_by_threat_level(
        self, threat_level: ThreatLevel, limit: int = 100
    ) -> List[FederatedEntity]:
        """Get entities by threat level."""
        result = []
        for entity in self._entities.values():
            if entity.threat_level == threat_level:
                result.append(entity)
                if len(result) >= limit:
                    break
        return result

    def delete_entity(self, entity_id: str) -> bool:
        """Delete an entity."""
        with self._lock:
            entity = self._entities.get(entity_id)
            if entity:
                del self._entities[entity_id]
                if entity.entity_id in self._entity_index.get(entity.entity_type, {}):
                    del self._entity_index[entity.entity_type][entity.entity_id]
                self._partner_entities[entity.partner_id].discard(entity_id)
                return True
            return False

    # Indicator Management
    def store_indicator(self, indicator: ThreatIndicator) -> None:
        """Store a threat indicator."""
        with self._lock:
            self._indicators[indicator.indicator_id] = indicator
            self._indicator_index[indicator.indicator_type].append(indicator.indicator_id)
            self._indicator_index[indicator.threat_type].append(indicator.indicator_id)

    def get_indicator(self, indicator_id: str) -> Optional[ThreatIndicator]:
        """Get indicator by ID."""
        return self._indicators.get(indicator_id)

    def get_indicators_by_type(
        self, indicator_type: str, limit: int = 100
    ) -> List[ThreatIndicator]:
        """Get indicators by type."""
        indicator_ids = self._indicator_index.get(indicator_type, [])[:limit]
        return [
            self._indicators[iid]
            for iid in indicator_ids
            if iid in self._indicators and not self._indicators[iid].is_expired()
        ]

    def get_active_indicators(
        self, threat_level: Optional[ThreatLevel] = None, limit: int = 100
    ) -> List[ThreatIndicator]:
        """Get all non-expired indicators."""
        result = []
        now = datetime.now(timezone.utc)
        for indicator in self._indicators.values():
            if indicator.expiration and indicator.expiration < now:
                continue
            if threat_level and indicator.threat_level != threat_level:
                continue
            result.append(indicator)
            if len(result) >= limit:
                break
        return result

    def search_indicators(
        self,
        query: str,
        threat_level: Optional[ThreatLevel] = None,
        limit: int = 100,
    ) -> List[ThreatIndicator]:
        """Search indicators by value pattern."""
        result = []
        query_lower = query.lower()
        for indicator in self._indicators.values():
            if indicator.is_expired():
                continue
            if query_lower not in indicator.value.lower():
                continue
            if threat_level and indicator.threat_level != threat_level:
                continue
            result.append(indicator)
            if len(result) >= limit:
                break
        return result

    # Network Management
    def store_network(self, network: FraudNetwork) -> None:
        """Store a fraud network."""
        with self._lock:
            self._networks[network.network_id] = network
            for node_id in network.nodes:
                self._network_members[network.network_id].add(node_id)

    def get_network(self, network_id: str) -> Optional[FraudNetwork]:
        """Get network by ID."""
        return self._networks.get(network_id)

    def get_networks_by_type(
        self, network_type: str, limit: int = 100
    ) -> List[FraudNetwork]:
        """Get networks by type."""
        result = []
        for network in self._networks.values():
            if network.network_type.value == network_type:
                result.append(network)
                if len(result) >= limit:
                    break
        return result

    def get_networks_by_entity(self, entity_id: str) -> List[FraudNetwork]:
        """Get networks containing an entity."""
        result = []
        for network in self._networks.values():
            if entity_id in network.nodes:
                result.append(network)
        return result

    def get_all_networks(self, limit: int = 100) -> List[FraudNetwork]:
        """Get all networks."""
        return list(self._networks.values())[:limit]

    # Campaign Management
    def store_campaign(self, campaign: FraudCampaign) -> None:
        """Store a fraud campaign."""
        with self._lock:
            self._campaigns[campaign.campaign_id] = campaign

    def get_campaign(self, campaign_id: str) -> Optional[FraudCampaign]:
        """Get campaign by ID."""
        return self._campaigns.get(campaign_id)

    def get_active_campaigns(self, limit: int = 100) -> List[FraudCampaign]:
        """Get active campaigns."""
        result = []
        for campaign in self._campaigns.values():
            if campaign.status == "active":
                result.append(campaign)
                if len(result) >= limit:
                    break
        return result

    def get_campaigns_by_threat_level(
        self, threat_level: ThreatLevel, limit: int = 100
    ) -> List[FraudCampaign]:
        """Get campaigns by threat level."""
        result = []
        for campaign in self._campaigns.values():
            if campaign.threat_level == threat_level:
                result.append(campaign)
                if len(result) >= limit:
                    break
        return result

    # Investigation Management
    def store_investigation(self, investigation: InvestigationCase) -> None:
        """Store an investigation case."""
        with self._lock:
            self._investigations[investigation.case_id] = investigation

    def get_investigation(self, case_id: str) -> Optional[InvestigationCase]:
        """Get investigation by ID."""
        return self._investigations.get(case_id)

    def get_investigations_by_status(
        self, status: InvestigationStatus, limit: int = 100
    ) -> List[InvestigationCase]:
        """Get investigations by status."""
        result = []
        for investigation in self._investigations.values():
            if investigation.status == status:
                result.append(investigation)
                if len(result) >= limit:
                    break
        return result

    def get_open_investigations(self, limit: int = 100) -> List[InvestigationCase]:
        """Get all open investigations."""
        return self.get_investigations_by_status(InvestigationStatus.OPEN, limit)

    def get_all_investigations(self, limit: int = 100) -> List[InvestigationCase]:
        """Get all investigations."""
        return list(self._investigations.values())[:limit]

    # Partner Management
    def store_partner(self, partner: FederationPartner) -> None:
        """Store a federation partner."""
        with self._lock:
            self._partners[partner.partner_id] = partner

    def get_partner(self, partner_id: str) -> Optional[FederationPartner]:
        """Get partner by ID."""
        return self._partners.get(partner_id)

    def get_active_partners(self) -> List[FederationPartner]:
        """Get all active partners."""
        return [
            p for p in self._partners.values() if p.status == FederationStatus.ACTIVE
        ]

    def get_all_partners(self) -> List[FederationPartner]:
        """Get all partners."""
        return list(self._partners.values())

    def delete_partner(self, partner_id: str) -> bool:
        """Delete a partner."""
        with self._lock:
            if partner_id in self._partners:
                del self._partners[partner_id]
                return True
            return False

    # Graph Management
    def store_graph_node(self, node: KnowledgeGraphNode) -> None:
        """Store a graph node."""
        with self._lock:
            self._graph_nodes[node.node_id] = node

    def get_graph_node(self, node_id: str) -> Optional[KnowledgeGraphNode]:
        """Get graph node by ID."""
        return self._graph_nodes.get(node_id)

    def store_graph_edge(self, edge: KnowledgeGraphEdge) -> None:
        """Store a graph edge."""
        with self._lock:
            self._graph_edges[edge.edge_id] = edge

    def get_graph_edge(self, edge_id: str) -> Optional[KnowledgeGraphEdge]:
        """Get graph edge by ID."""
        return self._graph_edges.get(edge_id)

    def get_node_edges(self, node_id: str) -> List[KnowledgeGraphEdge]:
        """Get all edges connected to a node."""
        return [
            e
            for e in self._graph_edges.values()
            if e.source_id == node_id or e.target_id == node_id
        ]

    def get_graph_snapshot(
        self, center_node_id: str, depth: int = 2
    ) -> Dict[str, Any]:
        """Get a subgraph snapshot centered on a node."""
        nodes = {center_node_id}
        edges = []
        current_depth = {center_node_id: 0}
        queue = [center_node_id]

        while queue:
            current = queue.pop(0)
            current_d = current_depth[current]

            if current_d >= depth:
                continue

            for edge in self.get_node_edges(current):
                edges.append(edge)
                if edge.source_id == current and edge.target_id not in nodes:
                    nodes.add(edge.target_id)
                    queue.append(edge.target_id)
                    current_depth[edge.target_id] = current_d + 1
                elif edge.target_id == current and edge.source_id not in nodes:
                    nodes.add(edge.source_id)
                    queue.append(edge.source_id)
                    current_depth[edge.source_id] = current_d + 1

        return {
            "nodes": [self._graph_nodes.get(n) for n in nodes if n in self._graph_nodes],
            "edges": edges,
            "center": center_node_id,
            "depth": depth,
        }

    # Audit Management
    def store_audit_record(self, record: AuditRecord) -> None:
        """Store an audit record."""
        with self._lock:
            self._audit_records.append(record)
            # Keep only last 10000 records
            if len(self._audit_records) > 10000:
                self._audit_records = self._audit_records[-10000:]

    def get_audit_records(
        self,
        partner_id: Optional[str] = None,
        user_id: Optional[str] = None,
        operation: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditRecord]:
        """Query audit records."""
        result = []
        for record in reversed(self._audit_records):
            if partner_id and record.partner_id != partner_id:
                continue
            if user_id and record.user_id != user_id:
                continue
            if operation and record.operation != operation:
                continue
            result.append(record)
            if len(result) >= limit:
                break
        return result

    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        active_indicators = sum(
            1 for i in self._indicators.values() if not i.is_expired()
        )
        open_investigations = sum(
            1 for i in self._investigations.values()
            if i.status in (InvestigationStatus.OPEN, InvestigationStatus.IN_PROGRESS)
        )
        active_campaigns = sum(1 for c in self._campaigns.values() if c.status == "active")
        active_partners = sum(
            1 for p in self._partners.values() if p.status == FederationStatus.ACTIVE
        )

        threat_dist = {}
        for entity in self._entities.values():
            level = entity.threat_level.value
            threat_dist[level] = threat_dist.get(level, 0) + 1

        return {
            "total_entities": len(self._entities),
            "total_indicators": len(self._indicators),
            "active_indicators": active_indicators,
            "total_networks": len(self._networks),
            "total_campaigns": len(self._campaigns),
            "active_campaigns": active_campaigns,
            "total_investigations": len(self._investigations),
            "open_investigations": open_investigations,
            "total_partners": len(self._partners),
            "active_partners": active_partners,
            "graph_nodes": len(self._graph_nodes),
            "graph_edges": len(self._graph_edges),
            "audit_records": len(self._audit_records),
            "threat_distribution": threat_dist,
        }


# Global store instance
_store: Optional[GlobalIntelligenceStore] = None


def get_global_intelligence_store() -> GlobalIntelligenceStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        _store = GlobalIntelligenceStore()
    return _store


def reset_store() -> None:
    """Reset the store (for testing)."""
    global _store
    _store = None