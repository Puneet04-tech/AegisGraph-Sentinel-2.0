"""
Threat Correlation Engine.

Correlates threats across institutions and campaigns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import uuid

from .models import CrossCorrelation, FraudCampaign, ThreatCampaignStatus, ThreatIntelligence
from .store import GlobalDefenseStore, get_global_defense_store


@dataclass
class CorrelationInsight:
    """Insight from threat correlation."""
    insight_type: str
    description: str
    confidence: float
    affected_institutions: List[str] = field(default_factory=list)


class ThreatCorrelationEngine:
    """Engine for cross-institution threat correlation."""

    def __init__(self, store: Optional[GlobalDefenseStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_global_defense_store()

    async def correlate_threats(
        self,
        institution_1: str,
        institution_2: str,
        threat_type: Optional[str] = None,
    ) -> CrossCorrelation:
        """Correlate threats between two institutions."""
        intel_1 = self._get_institution_intel(institution_1, threat_type)
        intel_2 = self._get_institution_intel(institution_2, threat_type)
        
        shared_indicators = self._find_shared_indicators(intel_1, intel_2)
        confidence = self._calculate_correlation_confidence(shared_indicators, len(intel_1), len(intel_2))
        threat_level = self._assess_threat_level(shared_indicators, confidence)
        
        correlation = CrossCorrelation(
            correlation_id=str(uuid.uuid4()),
            institution_1=institution_1,
            institution_2=institution_2,
            correlation_type="shared_threat_indicators",
            confidence=confidence,
            threat_level=threat_level,
            shared_indicators=shared_indicators,
        )
        
        self.store.store_correlation(correlation)
        return correlation

    def _get_institution_intel(
        self,
        institution_id: str,
        threat_type: Optional[str] = None,
    ) -> List[ThreatIntelligence]:
        """Get intelligence from an institution."""
        all_intel = list(self.store._intelligence.values())
        if threat_type:
            return [i for i in all_intel if i.source_institution == institution_id and i.threat_type == threat_type]
        return [i for i in all_intel if i.source_institution == institution_id]

    def _find_shared_indicators(
        self,
        intel_1: List[ThreatIntelligence],
        intel_2: List[ThreatIntelligence],
    ) -> List[str]:
        """Find shared indicators between institutions."""
        indicators_1 = self._extract_indicators(intel_1)
        indicators_2 = self._extract_indicators(intel_2)
        return list(indicators_1 & indicators_2)

    def _extract_indicators(self, intel_list: List[ThreatIntelligence]) -> Set[str]:
        """Extract unique indicators from intelligence list."""
        indicators: Set[str] = set()
        for intel in intel_list:
            for ind in intel.indicators:
                if "hash" in ind:
                    indicators.add(f"hash:{ind['hash']}")
                if "ip" in ind:
                    indicators.add(f"ip:{ind['ip']}")
                if "email" in ind:
                    indicators.add(f"email:{ind['email']}")
                if "pattern" in ind:
                    indicators.add(f"pattern:{ind['pattern']}")
        return indicators

    def _calculate_correlation_confidence(
        self,
        shared: List[str],
        count_1: int,
        count_2: int,
    ) -> float:
        """Calculate correlation confidence."""
        if not shared:
            return 0.0
        
        overlap = len(shared)
        total = len(shared) + (count_1 - overlap) + (count_2 - overlap)
        
        jaccard = overlap / total if total > 0 else 0
        return min(0.95, 0.5 + (jaccard * 0.5))

    def _assess_threat_level(
        self,
        shared_indicators: List[str],
        confidence: float,
    ) -> float:
        """Assess threat level from correlation."""
        if len(shared_indicators) >= 5 and confidence > 0.7:
            return 0.9
        elif len(shared_indicators) >= 3 and confidence > 0.5:
            return 0.7
        elif len(shared_indicators) >= 1:
            return 0.5
        return 0.2

    async def correlate_campaign_threats(self, campaign_id: str) -> List[CorrelationInsight]:
        """Correlate threats within a campaign."""
        campaign = self.store.get_campaign(campaign_id)
        if not campaign:
            return []
        
        insights: List[CorrelationInsight] = []
        
        affected = campaign.affected_institutions
        for i, inst_1 in enumerate(affected):
            for inst_2 in affected[i + 1:]:
                correlation = await self.correlate_threats(inst_1, inst_2)
                if correlation.confidence > 0.5:
                    insights.append(CorrelationInsight(
                        insight_type="campaign_correlation",
                        description=f"High correlation ({correlation.confidence:.0%}) between {inst_1} and {inst_2}",
                        confidence=correlation.confidence,
                        affected_institutions=[inst_1, inst_2],
                    ))
        
        return insights

    def get_cross_border_patterns(self) -> List[Dict[str, Any]]:
        """Identify cross-border fraud patterns."""
        patterns: List[Dict[str, Any]] = []
        
        for intel in self.store._intelligence.values():
            regions = set()
            for ind in intel.indicators:
                if "region" in ind:
                    regions.add(ind["region"])
            
            if len(regions) >= 2:
                patterns.append({
                    "threat_type": intel.threat_type,
                    "regions": list(regions),
                    "indicator_count": len(intel.indicators),
                    "confidence": intel.confidence,
                })
        
        return patterns


# Singleton instance
_engine: Optional[ThreatCorrelationEngine] = None


def get_threat_correlation_engine() -> ThreatCorrelationEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = ThreatCorrelationEngine()
    return _engine


def reset_threat_correlation_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None