"""
Cyber Threat Intelligence Engine.

Main service for CTI operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    Campaign,
    EnrichmentResult,
    FeedSource,
    IOC,
    IOCType,
    ThreatActor,
    ThreatCategory,
    ThreatFeed,
    ThreatLevel,
    ThreatScore,
)
from .store import CTIStore, get_cti_store


class CTIEngine:
    """Main CTI engine."""

    def __init__(self, store: Optional[CTIStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_cti_store()

    def add_ioc(
        self,
        indicator_type: str,
        value: str,
        threat_level: str,
        confidence: float = 0.5,
        tags: Optional[List[str]] = None,
        source: Optional[str] = None,
    ) -> IOC:
        """Add an IOC."""
        ioc_id = f"ioc-{uuid.uuid4().hex[:12]}"
        
        ioc = IOC(
            ioc_id=ioc_id,
            indicator_type=IOCType(indicator_type),
            value=value,
            threat_level=ThreatLevel(threat_level),
            confidence=confidence,
            tags=tags or [],
            source=source,
        )
        
        self.store.add_ioc(ioc)
        
        self.store.log_audit(
            user_id="system",
            action="ioc_added",
            resource_type="ioc",
            resource_id=ioc_id,
            details={"type": indicator_type, "value": value},
        )
        
        return ioc

    def get_ioc(self, ioc_id: str) -> Optional[Dict[str, Any]]:
        """Get IOC details."""
        ioc = self.store.get_ioc(ioc_id)
        if not ioc:
            return None
        
        return self._ioc_to_dict(ioc)

    def _ioc_to_dict(self, ioc: IOC) -> Dict[str, Any]:
        """Convert IOC to dict."""
        return {
            "ioc_id": ioc.ioc_id,
            "type": ioc.indicator_type.value,
            "value": ioc.value,
            "threat_level": ioc.threat_level.value,
            "confidence": ioc.confidence,
            "tags": ioc.tags,
            "source": ioc.source,
            "first_seen": ioc.first_seen.isoformat(),
            "last_seen": ioc.last_seen.isoformat(),
        }

    def search_iocs(
        self,
        query: str,
        ioc_type: Optional[str] = None,
        threat_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search IOCs."""
        results = self.store.search_iocs(query)
        
        if ioc_type:
            type_enum = IOCType(ioc_type)
            results = [i for i in results if i.indicator_type == type_enum]
        
        if threat_level:
            level_enum = ThreatLevel(threat_level)
            results = [i for i in results if i.threat_level == level_enum]
        
        return [self._ioc_to_dict(i) for i in results]

    def add_threat_actor(
        self,
        name: str,
        category: str,
        motivation: Optional[List[str]] = None,
        capabilities: Optional[List[str]] = None,
    ) -> ThreatActor:
        """Add a threat actor."""
        actor_id = f"actor-{uuid.uuid4().hex[:12]}"
        
        actor = ThreatActor(
            actor_id=actor_id,
            name=name,
            category=ThreatCategory(category),
            motivation=motivation or [],
            capabilities=capabilities or [],
        )
        
        self.store.add_actor(actor)
        
        return actor

    def add_campaign(
        self,
        name: str,
        description: str,
        actors: Optional[List[str]] = None,
        iocs: Optional[List[str]] = None,
    ) -> Campaign:
        """Add a campaign."""
        campaign_id = f"camp-{uuid.uuid4().hex[:12]}"
        
        campaign = Campaign(
            campaign_id=campaign_id,
            name=name,
            description=description,
            actors=actors or [],
            iocs=iocs or [],
        )
        
        self.store.add_campaign(campaign)
        
        return campaign

    def add_feed(
        self,
        name: str,
        source: str,
        url: Optional[str] = None,
    ) -> ThreatFeed:
        """Add a threat feed."""
        feed_id = f"feed-{uuid.uuid4().hex[:12]}"
        
        feed = ThreatFeed(
            feed_id=feed_id,
            name=name,
            source=FeedSource(source),
            url=url,
        )
        
        self.store.add_feed(feed)
        
        return feed

    def enrich_ioc(self, ioc_id: str) -> Dict[str, Any]:
        """Enrich an IOC."""
        ioc = self.store.get_ioc(ioc_id)
        if not ioc:
            return {"success": False, "error": "IOC not found"}
        
        enriched_data = {
            "reputation": self._calculate_reputation(ioc),
            "threat_actors": self._find_related_actors(ioc),
            "campaigns": self._find_related_campaigns(ioc),
            "geolocation": self._estimate_geolocation(ioc),
        }
        
        enrichment = EnrichmentResult(
            enrichment_id=str(uuid.uuid4()),
            ioc_id=ioc_id,
            enriched_data=enriched_data,
            providers_used=["internal"],
        )
        
        self.store.store_enrichment(enrichment)
        
        return {
            "success": True,
            "enrichment": enriched_data,
        }

    def _calculate_reputation(self, ioc: IOC) -> float:
        """Calculate reputation score."""
        score = ioc.confidence * 0.5
        
        if ioc.threat_level == ThreatLevel.CRITICAL:
            score += 0.4
        elif ioc.threat_level == ThreatLevel.HIGH:
            score += 0.3
        
        return min(1.0, score)

    def _find_related_actors(self, ioc: IOC) -> List[str]:
        """Find related threat actors."""
        return []

    def _find_related_campaigns(self, ioc: IOC) -> List[str]:
        """Find related campaigns."""
        return []

    def _estimate_geolocation(self, ioc: IOC) -> Optional[Dict[str, Any]]:
        """Estimate geolocation."""
        if ioc.indicator_type == IOCType.IP:
            return {"country": "Unknown", "confidence": 0.3}
        return None

    def calculate_threat_score(
        self,
        entity_type: str,
        entity_value: str,
    ) -> ThreatScore:
        """Calculate threat score."""
        iocs = self.store.search_iocs(entity_value)
        
        component_scores = {
            "ioc_match": len(iocs) / 10.0 if iocs else 0.0,
            "threat_level": 0.0,
        }
        
        if iocs:
            max_level = max(iocs, key=lambda x: list(ThreatLevel).index(x.threat_level))
            component_scores["threat_level"] = {
                ThreatLevel.CRITICAL: 1.0,
                ThreatLevel.HIGH: 0.75,
                ThreatLevel.MEDIUM: 0.5,
                ThreatLevel.LOW: 0.25,
                ThreatLevel.UNKNOWN: 0.0,
            }.get(max_level.threat_level, 0.0)
        
        overall = sum(component_scores.values()) / len(component_scores)
        
        score = ThreatScore(
            score_id=str(uuid.uuid4()),
            entity_type=entity_type,
            entity_value=entity_value,
            overall_score=overall,
            component_scores=component_scores,
        )
        
        self.store.store_score(score)
        
        return score

    def get_dashboard(self) -> Dict[str, Any]:
        """Get dashboard."""
        metrics = self.store.get_dashboard_metrics()
        iocs = self.store.search_iocs("")[:5]
        
        return {
            **metrics,
            "recent_iocs": [self._ioc_to_dict(i) for i in iocs],
        }

    def get_audit(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log."""
        events = self.store.get_audit_log(limit)
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "action": e.action,
                "resource_type": e.resource_type,
            }
            for e in events
        ]


# Singleton instance
_engine: Optional[CTIEngine] = None


def get_cti_engine() -> CTIEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = CTIEngine()
    return _engine


def reset_cti_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None