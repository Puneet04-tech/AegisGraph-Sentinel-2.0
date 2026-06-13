"""Feed Intelligence Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import ThreatFeed, IOC, IOCType, FeedStatus

class FeedIntelligenceService:
    """Threat Intelligence Feed Aggregation Service"""
    
    def __init__(self) -> None:
        self.feeds: Dict[str, ThreatFeed] = {}
        self.iocs: Dict[str, IOC] = {}
        self._init_default_feeds()
    
    def _init_default_feeds(self) -> None:
        """Initialize default threat feeds"""
        feeds = [
            ThreatFeed(
                feed_id="feed-001",
                name="AlienVault OTX",
                description="Open Threat Exchange",
                feed_type="Community",
                source_url="https://otx.alienvault.com",
                status=FeedStatus.ACTIVE,
                reliability_score=0.85
            ),
            ThreatFeed(
                feed_id="feed-002",
                name="Abuse.ch URLhaus",
                description="Malware URL exchange",
                feed_type="Security",
                source_url="https://urlhaus.abuse.ch",
                status=FeedStatus.ACTIVE,
                reliability_score=0.90
            )
        ]
        for feed in feeds:
            self.feeds[feed.feed_id] = feed
    
    def register_feed(
        self,
        name: str,
        description: str,
        feed_type: str,
        source_url: str
    ) -> Dict[str, Any]:
        """Register a new threat feed"""
        feed = ThreatFeed(
            feed_id=str(uuid4())[:8],
            name=name,
            description=description,
            feed_type=feed_type,
            source_url=source_url,
            status=FeedStatus.ACTIVE
        )
        self.feeds[feed.feed_id] = feed
        return feed.to_dict()
    
    def get_feed(self, feed_id: str) -> Optional[Dict[str, Any]]:
        """Get a feed"""
        feed = self.feeds.get(feed_id)
        return feed.to_dict() if feed else None
    
    def get_all_feeds(self) -> List[Dict[str, Any]]:
        """Get all feeds"""
        return [f.to_dict() for f in self.feeds.values()]
    
    def add_ioc(
        self,
        value: str,
        ioc_type: str,
        feed_id: str,
        threat_type: str,
        confidence: float,
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Add an IOC to the feed"""
        feed = self.feeds.get(feed_id)
        if not feed:
            raise ValueError(f"Feed {feed_id} not found")
        
        ioc = IOC(
            ioc_id=str(uuid4())[:8],
            value=value,
            ioc_type=IOCType(ioc_type),
            feed_id=feed_id,
            threat_type=threat_type,
            confidence=confidence,
            first_seen=datetime.utcnow(),
            tags=tags or []
        )
        self.iocs[ioc.ioc_id] = ioc
        feed.ioc_count += 1
        feed.last_updated = datetime.utcnow()
        return ioc.to_dict()
    
    def get_ioc(self, ioc_id: str) -> Optional[Dict[str, Any]]:
        """Get an IOC"""
        ioc = self.iocs.get(ioc_id)
        return ioc.to_dict() if ioc else None
    
    def search_iocs(
        self,
        ioc_type: Optional[str] = None,
        threat_type: Optional[str] = None,
        min_confidence: float = 0.0
    ) -> List[Dict[str, Any]]:
        """Search IOCs"""
        results = []
        for ioc in self.iocs.values():
            if ioc_type and ioc.ioc_type.value != ioc_type:
                continue
            if threat_type and ioc.threat_type != threat_type:
                continue
            if ioc.confidence < min_confidence:
                continue
            results.append(ioc.to_dict())
        return results
    
    def get_iocs_by_feed(self, feed_id: str) -> List[Dict[str, Any]]:
        """Get IOCs from a specific feed"""
        return [i.to_dict() for i in self.iocs.values() if i.feed_id == feed_id]
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get feed intelligence dashboard"""
        type_counts: Dict[str, int] = {}
        feed_counts: Dict[str, int] = {}
        for ioc in self.iocs.values():
            type_counts[ioc.ioc_type.value] = type_counts.get(ioc.ioc_type.value, 0) + 1
            feed_counts[ioc.feed_id] = feed_counts.get(ioc.feed_id, 0) + 1
        
        return {
            "total_feeds": len(self.feeds),
            "total_iocs": len(self.iocs),
            "active_feeds": len([f for f in self.feeds.values() if f.status == FeedStatus.ACTIVE]),
            "iocs_by_type": type_counts,
            "iocs_by_feed": feed_counts
        }


_feed_service: Optional[FeedIntelligenceService] = None

def get_feed_service() -> FeedIntelligenceService:
    """Get the global service instance"""
    global _feed_service
    if _feed_service is None:
        _feed_service = FeedIntelligenceService()
    return _feed_service