"""
Campaign Discovery Engine for multi-institution fraud campaign detection.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from .models import (
    FraudCampaign,
    FraudNetwork,
    NetworkType,
    ThreatIndicator,
    ThreatLevel,
    EntityType,
    FederatedEntity,
)
from .store import GlobalIntelligenceStore, get_global_intelligence_store
from .knowledge_graph import KnowledgeGraphEngine, get_knowledge_graph_engine
from .entity_correlation import EntityCorrelationEngine, get_entity_correlation_engine


@dataclass
class CampaignAnalysis:
    """Analysis result for a fraud campaign."""
    analysis_id: str
    campaign_id: str
    analysis_type: str
    findings: List[str]
    statistics: Dict[str, Any]
    affected_entities: List[str]
    recommended_actions: List[str]
    confidence_score: float
    analyzed_at: datetime


@dataclass
class CampaignDiscoveryConfig:
    """Configuration for campaign discovery."""
    min_campaign_size: int = 5
    correlation_threshold: float = 0.7
    temporal_window_hours: int = 72
    geographic_cluster_radius_km: float = 100.0
    auto_create_campaigns: bool = True


class CampaignDiscoveryEngine:
    """
    Discovers multi-institution fraud campaigns.

    Handles:
    - Campaign pattern detection
    - Cross-institution campaign correlation
    - Campaign analysis and attribution
    - Fraud campaign tracking
    """

    def __init__(
        self,
        store: Optional[GlobalIntelligenceStore] = None,
        graph_engine: Optional[KnowledgeGraphEngine] = None,
        correlation_engine: Optional[EntityCorrelationEngine] = None,
        config: Optional[CampaignDiscoveryConfig] = None,
    ):
        self._store = store or get_global_intelligence_store()
        self._graph = graph_engine or get_knowledge_graph_engine()
        self._correlation = correlation_engine or get_entity_correlation_engine()
        self._config = config or CampaignDiscoveryConfig()

    def discover_campaigns(
        self,
        entity_ids: Optional[List[str]] = None,
        time_window_hours: int = 72,
    ) -> List[FraudCampaign]:
        """Discover fraud campaigns from entities."""
        campaigns = []

        if entity_ids:
            entities = [self._store.get_entity(eid) for eid in entity_ids if self._store.get_entity(eid)]
        else:
            entities = list(self._store._entities.values())

        # Group entities by potential campaign
        groups = self._group_entities_by_pattern(entities, time_window_hours)

        for group_id, group_entities in groups.items():
            if len(group_entities) < self._config.min_campaign_size:
                continue

            # Analyze the group
            campaign = self._create_campaign_from_group(group_id, group_entities)
            if campaign:
                campaigns.append(campaign)
                self._store.store_campaign(campaign)

        return campaigns

    def analyze_campaign(
        self,
        campaign_id: str,
    ) -> CampaignAnalysis:
        """Analyze a fraud campaign in detail."""
        campaign = self._store.get_campaign(campaign_id)
        if not campaign:
            return CampaignAnalysis(
                analysis_id=str(uuid.uuid4()),
                campaign_id=campaign_id,
                analysis_type="unknown",
                findings=[],
                statistics={},
                affected_entities=[],
                recommended_actions=[],
                confidence_score=0.0,
                analyzed_at=datetime.now(timezone.utc),
            )

        findings = []
        statistics: Dict[str, Any] = {}
        entities = []
        recommendations = []

        # Analyze campaign indicators
        indicator_types = defaultdict(int)
        for indicator in campaign.indicators:
            indicator_types[indicator.indicator_type] += 1
            indicator_types[indicator.threat_type] += 1

        if indicator_types:
            findings.append(f"Contains {len(campaign.indicators)} threat indicators")
            statistics["indicator_distribution"] = dict(indicator_types)

        # Analyze affected institutions
        if campaign.affected_institutions:
            findings.append(
                f"Affects {len(campaign.affected_institutions)} institutions"
            )
            statistics["institution_count"] = len(campaign.affected_institutions)

        # Calculate statistics
        if campaign.victim_count > 0:
            statistics["victim_count"] = campaign.victim_count
            statistics["avg_loss_per_victim"] = (
                campaign.total_loss / campaign.victim_count
                if campaign.victim_count > 0
                else 0
            )

        # Get associated entities
        for network_id in campaign.associated_networks:
            network = self._store.get_network(network_id)
            if network:
                entities.extend(network.nodes)

        statistics["associated_entities"] = len(entities)
        statistics["total_loss"] = campaign.total_loss

        # Generate recommendations
        recommendations = self._generate_recommendations(campaign, statistics)

        # Calculate confidence
        confidence = self._calculate_campaign_confidence(campaign, statistics)

        return CampaignAnalysis(
            analysis_id=str(uuid.uuid4()),
            campaign_id=campaign_id,
            analysis_type="detailed",
            findings=findings,
            statistics=statistics,
            affected_entities=entities[:100],
            recommended_actions=recommendations,
            confidence_score=confidence,
            analyzed_at=datetime.now(timezone.utc),
        )

    def link_campaign_to_network(
        self,
        campaign_id: str,
        network_id: str,
    ) -> bool:
        """Link a campaign to a fraud network."""
        campaign = self._store.get_campaign(campaign_id)
        network = self._store.get_network(network_id)

        if not campaign or not network:
            return False

        if network_id not in campaign.associated_networks:
            campaign.associated_networks.append(network_id)
            self._store.store_campaign(campaign)

        if campaign_id not in network.associated_campaigns:
            network.associated_campaigns.append(campaign_id)
            self._store.store_network(network)

        return True

    def get_campaign_timeline(
        self,
        campaign_id: str,
    ) -> List[Dict[str, Any]]:
        """Get timeline of campaign events."""
        campaign = self._store.get_campaign(campaign_id)
        if not campaign:
            return []

        events = []

        # Start event
        events.append({
            "date": campaign.start_date,
            "type": "campaign_start",
            "description": f"Campaign '{campaign.campaign_name}' started",
        })

        # End event if exists
        if campaign.end_date:
            events.append({
                "date": campaign.end_date,
                "type": "campaign_end",
                "description": "Campaign ended",
            })

        # Sort by date
        events.sort(key=lambda e: e["date"])

        return events

    def update_campaign_status(
        self,
        campaign_id: str,
        status: str,
    ) -> bool:
        """Update campaign status."""
        campaign = self._store.get_campaign(campaign_id)
        if not campaign:
            return False

        campaign.status = status
        if status == "closed":
            campaign.end_date = datetime.now(timezone.utc)

        self._store.store_campaign(campaign)
        return True

    def _group_entities_by_pattern(
        self,
        entities: List[FederatedEntity],
        time_window_hours: int,
    ) -> Dict[str, List[FederatedEntity]]:
        """Group entities by potential campaign pattern."""
        groups: Dict[str, List[FederatedEntity]] = defaultdict(list)
        time_window = timedelta(hours=time_window_hours)

        for entity in entities:
            # Group by threat level and type
            if entity.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                key = f"high_risk_{entity.entity_type.value}"
                groups[key].append(entity)

            # Group by shared attributes
            for key, value in entity.attributes.items():
                if key in ("ip_address", "device_fingerprint", "email"):
                    group_key = f"attr_{key}_{value}"
                    groups[group_key].append(entity)

        return groups

    def _create_campaign_from_group(
        self,
        group_id: str,
        entities: List[FederatedEntity],
    ) -> Optional[FraudCampaign]:
        """Create a campaign from a group of entities."""
        if len(entities) < self._config.min_campaign_size:
            return None

        # Calculate campaign properties
        threat_types = set()
        indicators = []
        total_risk = 0.0

        for entity in entities:
            threat_types.add(entity.threat_level.value)
            total_risk += entity.risk_score

            # Create indicators from entity
            indicator = ThreatIndicator(
                indicator_id=str(uuid.uuid4()),
                indicator_type=entity.entity_type.value,
                value=entity.entity_id,
                source=entity.metadata.get("source", "internal"),
                threat_type=entity.threat_level.value,
                threat_level=entity.threat_level,
                confidence=entity.risk_score,
                first_seen=entity.first_seen,
                last_seen=entity.last_updated,
                expiration=entity.last_updated + timedelta(days=30),
                partner_id=entity.partner_id,
            )
            indicators.append(indicator)

        # Determine threat level
        if ThreatLevel.CRITICAL.value in threat_types:
            threat_level = ThreatLevel.CRITICAL
        elif ThreatLevel.HIGH.value in threat_types:
            threat_level = ThreatLevel.HIGH
        else:
            threat_level = ThreatLevel.MEDIUM

        # Get unique partners
        partners = set(e.partner_id for e in entities)

        campaign = FraudCampaign(
            campaign_id=str(uuid.uuid4()),
            campaign_name=f"Campaign {group_id}",
            threat_type=", ".join(threat_types),
            threat_level=threat_level,
            start_date=min(e.first_seen for e in entities),
            end_date=None,
            affected_institutions=list(partners),
            victim_count=len(entities),
            total_loss=total_risk * 1000,  # Estimated
            confidence_score=min(1.0, len(entities) / 10),
            indicators=indicators,
            associated_networks=[],
            discovery_date=datetime.now(timezone.utc),
            status="active",
        )

        return campaign

    def _generate_recommendations(
        self,
        campaign: FraudCampaign,
        statistics: Dict[str, Any],
    ) -> List[str]:
        """Generate recommendations for campaign handling."""
        recommendations = []

        if campaign.threat_level == ThreatLevel.CRITICAL:
            recommendations.append("Escalate to security leadership immediately")
            recommendations.append("Consider notifying law enforcement")

        if statistics.get("victim_count", 0) > 10:
            recommendations.append("Mass victim campaign - review prevention controls")

        if statistics.get("total_loss", 0) > 100000:
            recommendations.append("High financial impact - prioritize investigation")

        recommendations.append("Share indicators with federation partners")
        recommendations.append("Update detection rules based on campaign patterns")

        return recommendations

    def _calculate_campaign_confidence(
        self,
        campaign: FraudCampaign,
        statistics: Dict[str, Any],
    ) -> float:
        """Calculate confidence score for campaign."""
        score = 0.5

        # More indicators = higher confidence
        score += min(0.2, len(campaign.indicators) * 0.02)

        # More institutions affected = higher confidence
        score += min(0.1, len(campaign.affected_institutions) * 0.02)

        # Higher threat level = higher confidence
        if campaign.threat_level == ThreatLevel.CRITICAL:
            score += 0.2
        elif campaign.threat_level == ThreatLevel.HIGH:
            score += 0.1

        return min(1.0, score)


# Global engine instance
_engine: Optional[CampaignDiscoveryEngine] = None


def get_campaign_discovery_engine() -> CampaignDiscoveryEngine:
    """Get the global campaign discovery engine instance."""
    global _engine
    if _engine is None:
        _engine = CampaignDiscoveryEngine()
    return _engine