"""
Campaign Attribution Service - Core business logic
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    ThreatActor,
    Campaign,
    Attribution,
    ThreatProfile,
    RiskAssessment,
    Infrastructure,
    CampaignStats,
    ActorType,
    CampaignStatus,
    ConfidenceLevel,
    InfrastructureType,
)
from .store import get_campaign_store, CampaignStore


class CampaignService:
    """
    Core service for campaign attribution operations.
    Provides discovery, correlation, and attribution capabilities.
    """

    def __init__(self, store: Optional[CampaignStore] = None):
        self._store = store or get_campaign_store()
        self._lock = threading.RLock()

    def create_campaign(
        self,
        name: str,
        description: str = "",
        target_sectors: Optional[List[str]] = None,
        target_geographies: Optional[List[str]] = None,
        attack_vectors: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> Campaign:
        """Create a new fraud campaign."""
        with self._lock:
            campaign = Campaign(
                name=name,
                description=description,
                status=CampaignStatus.ACTIVE,
                target_sectors=target_sectors or [],
                target_geographies=target_geographies or [],
                attack_vectors=attack_vectors or [],
                tags=tags or [],
            )
            self._store.store_campaign(campaign)
            return campaign

    def create_actor(
        self,
        name: str,
        actor_type: ActorType,
        description: str = "",
        motivation: Optional[List[str]] = None,
        capabilities: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> ThreatActor:
        """Create a new threat actor."""
        with self._lock:
            actor = ThreatActor(
                name=name,
                actor_type=actor_type,
                description=description,
                motivation=motivation or [],
                capabilities=capabilities or [],
                tags=tags or [],
                active_since=datetime.now(timezone.utc).isoformat(),
            )
            self._store.store_actor(actor)
            return actor

    def attribute_campaign(
        self,
        campaign_id: str,
        actor_id: str,
        confidence: ConfidenceLevel,
        evidence: Optional[List[str]] = None,
        method: str = "automated",
        attributed_by: str = "system",
    ) -> Optional[Attribution]:
        """Attribute a campaign to a threat actor."""
        with self._lock:
            campaign = self._store.get_campaign(campaign_id)
            actor = self._store.get_actor(actor_id)

            if not campaign or not actor:
                return None

            # Create attribution
            attribution = Attribution(
                campaign_id=campaign_id,
                actor_id=actor_id,
                confidence=confidence,
                evidence=evidence or [],
                attribution_method=method,
                attributed_by=attributed_by,
            )
            self._store.store_attribution(attribution)

            # Link campaign to actor
            self._store.link_campaign_to_actor(campaign_id, actor_id)

            # Update campaign attribution confidence
            campaign.attribution_confidence = confidence
            if confidence == ConfidenceLevel.HIGH:
                campaign.status = CampaignStatus.ATTRIBUTED
            campaign.attributed_at = datetime.now(timezone.utc).isoformat()
            self._store.store_campaign(campaign)

            # Update actor
            actor.last_activity = datetime.now(timezone.utc).isoformat()
            self._store.store_actor(actor)

            return attribution

    def discover_campaign(self, indicators: List[str]) -> List[Campaign]:
        """Discover potential campaigns based on indicators."""
        with self._lock:
            matches = []
            for campaign in self._store._campaigns.values():
                for indicator in indicators:
                    if indicator in campaign.linked_indicators:
                        matches.append(campaign)
                        break
            return matches

    def correlate_campaigns(self, campaign_ids: List[str]) -> Dict[str, Any]:
        """Correlate multiple campaigns to find common elements."""
        with self._lock:
            campaigns = [self._store.get_campaign(cid) for cid in campaign_ids]
            campaigns = [c for c in campaigns if c is not None]

            if len(campaigns) < 2:
                return {"error": "Need at least 2 campaigns to correlate"}

            common_sectors = set(campaigns[0].target_sectors)
            common_geographies = set(campaigns[0].target_geographies)
            common_infra = set(campaigns[0].linked_infrastructure)
            common_actors = set(campaigns[0].attributed_actors)

            for campaign in campaigns[1:]:
                common_sectors &= set(campaign.target_sectors)
                common_geographies &= set(campaign.target_geographies)
                common_infra &= set(campaign.linked_infrastructure)
                common_actors &= set(campaign.attributed_actors)

            return {
                "campaigns": [c.campaign_id for c in campaigns],
                "common_sectors": list(common_sectors),
                "common_geographies": list(common_geographies),
                "common_infrastructure": list(common_infra),
                "common_actors": list(common_actors),
                "correlation_strength": len(common_infra) + len(common_actors),
            }

    def analyze_campaign_evolution(self, campaign_id: str) -> Dict[str, Any]:
        """Analyze how a campaign has evolved over time."""
        campaign = self._store.get_campaign(campaign_id)
        if not campaign:
            return {"error": "Campaign not found"}

        return {
            "campaign_id": campaign_id,
            "status": campaign.status.value,
            "start_date": campaign.start_date,
            "end_date": campaign.end_date,
            "victim_count": campaign.victim_count,
            "estimated_damage": campaign.estimated_damage,
            "linked_indicators_count": len(campaign.linked_indicators),
            "linked_infrastructure_count": len(campaign.linked_infrastructure),
            "attribution_confidence": campaign.attribution_confidence.value,
        }

    def generate_threat_profile(self, entity_type: str, entity_id: str) -> Optional[ThreatProfile]:
        """Generate a complete threat profile."""
        with self._lock:
            if entity_type == "campaign":
                entity = self._store.get_campaign(entity_id)
            elif entity_type == "actor":
                entity = self._store.get_actor(entity_id)
            else:
                return None

            if not entity:
                return None

            profile = ThreatProfile(
                entity_type=entity_type,
                entity_id=entity_id,
                name=entity.name,
                risk_score=self._calculate_risk_score(entity),
                threat_level=self._determine_threat_level(entity),
            )

            if entity_type == "campaign":
                profile.indicators = entity.linked_indicators
                profile.infrastructure = entity.linked_infrastructure
                profile.capabilities = entity.attack_vectors
                profile.associated_entities = entity.attributed_actors
            else:
                profile.indicators = []
                profile.infrastructure = entity.linked_infrastructure
                profile.capabilities = entity.capabilities
                profile.associated_entities = entity.linked_campaigns

            self._store.store_profile(profile)
            return profile

    def _calculate_risk_score(self, entity: Any) -> float:
        """Calculate risk score for an entity."""
        if isinstance(entity, Campaign):
            base_score = min(entity.victim_count * 0.01, 0.5)
            damage_score = min(entity.estimated_damage / 1000000, 0.3)
            indicator_score = min(len(entity.linked_indicators) * 0.05, 0.2)
            return min(1.0, base_score + damage_score + indicator_score)
        elif isinstance(entity, ThreatActor):
            base_score = 0.3 if entity.is_active else 0.1
            capability_score = min(len(entity.capabilities) * 0.1, 0.4)
            campaign_score = min(len(entity.linked_campaigns) * 0.05, 0.3)
            return min(1.0, base_score + capability_score + campaign_score)
        return 0.5

    def _determine_threat_level(self, entity: Any) -> str:
        """Determine threat level from risk score."""
        score = self._calculate_risk_score(entity)
        if score >= 0.8:
            return "critical"
        elif score >= 0.6:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.2:
            return "low"
        return "negligible"

    def assess_risk(self, entity_type: str, entity_id: str) -> Optional[RiskAssessment]:
        """Perform risk assessment for an entity."""
        with self._lock:
            if entity_type == "campaign":
                entity = self._store.get_campaign(entity_id)
            elif entity_type == "actor":
                entity = self._store.get_actor(entity_id)
            else:
                return None

            if not entity:
                return None

            risk_score = self._calculate_risk_score(entity)
            likelihood = self._calculate_likelihood(entity)
            impact = self._calculate_impact(entity)

            assessment = RiskAssessment(
                entity_type=entity_type,
                entity_id=entity_id,
                risk_score=risk_score,
                threat_level=self._determine_threat_level(entity),
                likelihood=likelihood,
                impact=impact,
                factors={
                    "risk_score": risk_score,
                    "likelihood": likelihood,
                    "impact": impact,
                },
                recommendations=self._generate_recommendations(entity),
            )

            return assessment

    def _calculate_likelihood(self, entity: Any) -> float:
        """Calculate likelihood of future activity."""
        if isinstance(entity, ThreatActor):
            if not entity.is_active:
                return 0.2
            return 0.7
        elif isinstance(entity, Campaign):
            if entity.status == CampaignStatus.ACTIVE:
                return 0.8
            return 0.3
        return 0.5

    def _calculate_impact(self, entity: Any) -> float:
        """Calculate potential impact."""
        if isinstance(entity, Campaign):
            return min(entity.estimated_damage / 1000000, 1.0)
        elif isinstance(entity, ThreatActor):
            return min(len(entity.linked_campaigns) * 0.2, 1.0)
        return 0.5

    def _generate_recommendations(self, entity: Any) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        risk_score = self._calculate_risk_score(entity)

        if risk_score >= 0.7:
            recommendations.append("Immediate investigation required")
            recommendations.append("Consider blocking associated infrastructure")

        if risk_score >= 0.5:
            recommendations.append("Enhanced monitoring recommended")
            recommendations.append("Review and update detection rules")

        if isinstance(entity, Campaign):
            if entity.linked_infrastructure:
                recommendations.append("Block identified infrastructure")
            if entity.attributed_actors:
                recommendations.append("Hunt for related campaigns")

        recommendations.append("Update threat intelligence feeds")
        return recommendations

    def add_infrastructure(
        self,
        ip_addresses: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
        infra_type: InfrastructureType = InfrastructureType.UNKNOWN,
    ) -> Infrastructure:
        """Add new infrastructure to track."""
        with self._lock:
            infra = Infrastructure(
                ip_addresses=ip_addresses or [],
                domains=domains or [],
                infrastructure_type=infra_type,
            )
            self._store.store_infrastructure(infra)
            return infra

    def link_infrastructure_to_campaign(self, infra_id: str, campaign_id: str) -> bool:
        """Link infrastructure to a campaign."""
        return self._store.link_infrastructure_to_campaign(infra_id, campaign_id)

    def get_campaign_statistics(self) -> CampaignStats:
        """Get campaign attribution statistics."""
        return self._store.get_stats()

    def search_campaigns(
        self,
        status: Optional[CampaignStatus] = None,
        sector: Optional[str] = None,
        geography: Optional[str] = None,
    ) -> List[Campaign]:
        """Search campaigns by criteria."""
        with self._lock:
            results = list(self._store._campaigns.values())

            if status:
                results = [c for c in results if c.status == status]
            if sector:
                results = [c for c in results if sector in c.target_sectors]
            if geography:
                results = [c for c in results if geography in c.target_geographies]

            return results

    def search_actors(
        self,
        actor_type: Optional[ActorType] = None,
        is_active: Optional[bool] = None,
    ) -> List[ThreatActor]:
        """Search actors by criteria."""
        with self._lock:
            results = list(self._store._actors.values())

            if actor_type:
                results = [a for a in results if a.actor_type == actor_type]
            if is_active is not None:
                results = [a for a in results if a.is_active == is_active]

            return results


# Singleton instance
_campaign_service: Optional[CampaignService] = None
_service_lock = threading.Lock()


def get_campaign_service() -> CampaignService:
    """Get the singleton CampaignService instance."""
    global _campaign_service
    with _service_lock:
        if _campaign_service is None:
            _campaign_service = CampaignService()
        return _campaign_service


def reset_campaign_service() -> None:
    """Reset the singleton service (for testing)."""
    global _campaign_service
    with _service_lock:
        _campaign_service = None
