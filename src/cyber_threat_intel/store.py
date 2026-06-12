"""
Cyber Threat Intelligence Store.

Storage layer for CTI components.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    AuditEvent,
    Campaign,
    EnrichmentResult,
    FeedSource,
    IOC,
    IOCType,
    ThreatActor,
    ThreatFeed,
    ThreatLevel,
    ThreatScore,
)


class CTIStore:
    """Store for cyber threat intelligence."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._iocs: Dict[str, IOC] = {}
        self._actors: Dict[str, ThreatActor] = {}
        self._campaigns: Dict[str, Campaign] = {}
        self._feeds: Dict[str, ThreatFeed] = {}
        self._enrichments: Dict[str, EnrichmentResult] = {}
        self._scores: Dict[str, ThreatScore] = {}
        self._audit_log: List[AuditEvent] = []
        self._lock = threading.RLock()

    def add_ioc(self, ioc: IOC) -> None:
        """Add an IOC."""
        with self._lock:
            self._iocs[ioc.ioc_id] = ioc

    def get_ioc(self, ioc_id: str) -> Optional[IOC]:
        """Get an IOC."""
        return self._iocs.get(ioc_id)

    def get_iocs_by_type(self, ioc_type: IOCType) -> List[IOC]:
        """Get IOCs by type."""
        return [i for i in self._iocs.values() if i.indicator_type == ioc_type]

    def get_iocs_by_level(self, level: ThreatLevel) -> List[IOC]:
        """Get IOCs by threat level."""
        return [i for i in self._iocs.values() if i.threat_level == level]

    def search_iocs(self, query: str) -> List[IOC]:
        """Search IOCs."""
        query_lower = query.lower()
        return [
            i for i in self._iocs.values()
            if query_lower in i.value.lower() or
            any(query_lower in tag.lower() for tag in i.tags)
        ]

    def add_actor(self, actor: ThreatActor) -> None:
        """Add a threat actor."""
        with self._lock:
            self._actors[actor.actor_id] = actor

    def get_actor(self, actor_id: str) -> Optional[ThreatActor]:
        """Get a threat actor."""
        return self._actors.get(actor_id)

    def add_campaign(self, campaign: Campaign) -> None:
        """Add a campaign."""
        with self._lock:
            self._campaigns[campaign.campaign_id] = campaign

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """Get a campaign."""
        return self._campaigns.get(campaign_id)

    def get_active_campaigns(self) -> List[Campaign]:
        """Get active campaigns."""
        return [c for c in self._campaigns.values() if c.status == "active"]

    def add_feed(self, feed: ThreatFeed) -> None:
        """Add a feed."""
        with self._lock:
            self._feeds[feed.feed_id] = feed

    def get_feed(self, feed_id: str) -> Optional[ThreatFeed]:
        """Get a feed."""
        return self._feeds.get(feed_id)

    def get_enabled_feeds(self) -> List[ThreatFeed]:
        """Get enabled feeds."""
        return [f for f in self._feeds.values() if f.enabled]

    def store_enrichment(self, enrichment: EnrichmentResult) -> None:
        """Store enrichment result."""
        with self._lock:
            self._enrichments[enrichment.ioc_id] = enrichment

    def get_enrichment(self, ioc_id: str) -> Optional[EnrichmentResult]:
        """Get enrichment for IOC."""
        return self._enrichments.get(ioc_id)

    def store_score(self, score: ThreatScore) -> None:
        """Store threat score."""
        with self._lock:
            self._scores[score.entity_value] = score

    def get_score(self, entity_value: str) -> Optional[ThreatScore]:
        """Get threat score."""
        return self._scores.get(entity_value)

    def log_audit(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """Log an audit event."""
        event = AuditEvent(
            event_id=f"audit-{len(self._audit_log) + 1}",
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            success=success,
        )
        with self._lock:
            self._audit_log.append(event)

    def get_audit_log(self, limit: int = 100) -> List[AuditEvent]:
        """Get audit log."""
        return self._audit_log[-limit:]

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get dashboard metrics."""
        iocs = list(self._iocs.values())
        
        return {
            "total_iocs": len(iocs),
            "critical_iocs": len([i for i in iocs if i.threat_level == ThreatLevel.CRITICAL]),
            "high_iocs": len([i for i in iocs if i.threat_level == ThreatLevel.HIGH]),
            "total_actors": len(self._actors),
            "active_campaigns": len(self.get_active_campaigns()),
            "enabled_feeds": len(self.get_enabled_feeds()),
        }

    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._iocs.clear()
            self._actors.clear()
            self._campaigns.clear()
            self._feeds.clear()
            self._enrichments.clear()
            self._scores.clear()
            self._audit_log.clear()


# Singleton instance
_store: Optional[CTIStore] = None
_store_lock = threading.Lock()


def get_cti_store() -> CTIStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = CTIStore()
    return _store


def reset_cti_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None