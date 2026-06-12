"""
Dark Web Intelligence Engine.

Monitors dark web for threat intelligence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import DarkWebIntelligence, RiskLevel
from .store import DRPStore, get_drp_store


class DarkWebIntelligenceEngine:
    """Engine for dark web intelligence gathering."""

    def __init__(self, store: Optional[DRPStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_drp_store()
        self._monitored_keywords: List[str] = []

    def add_monitored_keyword(self, keyword: str) -> None:
        """Add a keyword to monitor."""
        if keyword.lower() not in [k.lower() for k in self._monitored_keywords]:
            self._monitored_keywords.append(keyword)

    def add_intelligence(
        self,
        source: str,
        content_type: str,
        title: str,
        description: str,
        indicators: Optional[List[str]] = None,
        confidence: float = 0.5,
    ) -> DarkWebIntelligence:
        """Add dark web intelligence."""
        intel = DarkWebIntelligence(
            intel_id=f"dw-{uuid.uuid4().hex[:12]}",
            source=source,
            content_type=content_type,
            title=title,
            description=description,
            indicators=indicators or [],
            confidence=confidence,
            risk_level=self._calculate_risk_level(confidence),
        )
        
        self.store.add_darkweb_intel(intel)
        
        self.store.log_audit(
            user_id="system",
            action="darkweb_intelligence_added",
            resource_type="darkweb_intel",
            resource_id=intel.intel_id,
            details={"source": source, "content_type": content_type},
        )
        
        return intel

    def _calculate_risk_level(self, confidence: float) -> RiskLevel:
        """Calculate risk level from confidence."""
        if confidence >= 0.8:
            return RiskLevel.CRITICAL
        elif confidence >= 0.6:
            return RiskLevel.HIGH
        elif confidence >= 0.4:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def get_intelligence(
        self,
        min_confidence: float = 0.0,
        content_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get dark web intelligence."""
        intel_list = self.store.get_darkweb_intel(min_confidence)
        
        if content_type:
            intel_list = [i for i in intel_list if i.content_type == content_type]
        
        return [
            {
                "intel_id": i.intel_id,
                "source": i.source,
                "content_type": i.content_type,
                "title": i.title,
                "description": i.description,
                "indicators": i.indicators,
                "confidence": i.confidence,
                "risk_level": i.risk_level.value,
                "created_at": i.created_at.isoformat(),
            }
            for i in intel_list
        ]

    def search_intelligence(self, query: str) -> List[Dict[str, Any]]:
        """Search intelligence by query."""
        query_lower = query.lower()
        all_intel = self.store.get_darkweb_intel()
        
        results = []
        for intel in all_intel:
            if query_lower in intel.title.lower():
                results.append(intel)
            elif query_lower in intel.description.lower():
                results.append(intel)
            elif any(query_lower in ind.lower() for ind in intel.indicators):
                results.append(intel)
        
        return [
            {
                "intel_id": i.intel_id,
                "source": i.source,
                "title": i.title,
                "confidence": i.confidence,
                "risk_level": i.risk_level.value,
            }
            for i in results
        ]


# Singleton instance
_engine: Optional[DarkWebIntelligenceEngine] = None


def get_darkweb_intelligence_engine() -> DarkWebIntelligenceEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = DarkWebIntelligenceEngine()
    return _engine


def reset_darkweb_intelligence_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None