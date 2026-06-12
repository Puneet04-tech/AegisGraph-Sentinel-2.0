"""
Federated Intelligence Hub.

Central hub for federated threat intelligence sharing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    Institution,
    IntelligenceSharingLevel,
    ThreatIntelligence,
    TrustLevel,
)
from .store import GlobalDefenseStore, get_global_defense_store


@dataclass
class IntelligenceContribution:
    """Contribution summary from an institution."""
    institution_id: str
    intelligence_count: int
    avg_confidence: float
    last_contribution: Optional[datetime] = None


class FederatedIntelligenceHub:
    """Hub for federated intelligence sharing."""

    def __init__(self, store: Optional[GlobalDefenseStore] = None) -> None:
        """Initialize the hub."""
        self.store = store or get_global_defense_store()

    async def share_intelligence(
        self,
        source_institution: str,
        threat_type: str,
        indicators: List[Dict[str, Any]],
        confidence: float,
        sharing_level: str = "anonymized",
        tags: Optional[List[str]] = None,
    ) -> ThreatIntelligence:
        """Share threat intelligence with the network."""
        source = self.store.get_institution(source_institution)
        if not source:
            source = Institution(
                institution_id=source_institution,
                name=source_institution,
                trust_level=TrustLevel.PROVISIONAL,
            )
            self.store.add_institution(source)
        
        sharing = IntelligenceSharingLevel(sharing_level)
        
        if sharing == IntelligenceSharingLevel.FULL:
            processed_indicators = indicators
        elif sharing == IntelligenceSharingLevel.ANONYMIZED:
            processed_indicators = [
                self._anonymize_indicator(ind) for ind in indicators
            ]
        elif sharing == IntelligenceSharingLevel.SUMMARY:
            processed_indicators = [{"summary": ind.get("type", "unknown")} for ind in indicators[:3]]
        else:
            processed_indicators = [{"category": threat_type}]
        
        intelligence = ThreatIntelligence(
            intelligence_id=str(uuid.uuid4()),
            source_institution=source_institution,
            threat_type=threat_type,
            indicators=processed_indicators,
            confidence=confidence,
            sharing_level=sharing,
            tags=tags or [],
        )
        
        self.store.store_intelligence(intelligence)
        
        source.last_sync = datetime.now(timezone.utc)
        return intelligence

    def _anonymize_indicator(self, indicator: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize an indicator."""
        sensitive_fields = ["account_id", "ssn", "email", "phone", "address"]
        anonymized = indicator.copy()
        for field_name in sensitive_fields:
            if field_name in anonymized:
                value = str(anonymized[field_name])
                if len(value) > 4:
                    anonymized[field_name] = f"****{value[-4:]}"
                else:
                    anonymized[field_name] = "****"
        return anonymized

    def get_network_intelligence(
        self,
        threat_type: Optional[str] = None,
        min_confidence: float = 0.5,
        max_results: int = 100,
    ) -> List[ThreatIntelligence]:
        """Get intelligence from the network."""
        results = list(self.store._intelligence.values())
        
        if threat_type:
            results = [i for i in results if i.threat_type == threat_type]
        
        results = [i for i in results if i.confidence >= min_confidence]
        
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:max_results]

    def get_contribution_summary(self) -> List[IntelligenceContribution]:
        """Get contribution summary from all institutions."""
        contributions: Dict[str, List[ThreatIntelligence]] = {}
        
        for intel in self.store._intelligence.values():
            contributions.setdefault(intel.source_institution, []).append(intel)
        
        return [
            IntelligenceContribution(
                institution_id=inst_id,
                intelligence_count=len(intels),
                avg_confidence=sum(i.confidence for i in intels) / len(intels) if intels else 0,
                last_contribution=max(i.created_at for i in intels) if intels else None,
            )
            for inst_id, intels in contributions.items()
        ]

    def get_institutions_by_capability(self, capability: str) -> List[Institution]:
        """Get institutions with specific capability."""
        return [
            i for i in self.store.get_all_institutions()
            if capability in i.capabilities
        ]

    def validate_sharing_permission(
        self,
        source_id: str,
        target_id: str,
        sharing_level: IntelligenceSharingLevel,
    ) -> bool:
        """Validate if sharing is permitted between institutions."""
        source = self.store.get_institution(source_id)
        target = self.store.get_institution(target_id)
        
        if not source or not target:
            return False
        
        if source.trust_level == TrustLevel.RESTRICTED:
            return False
        
        if sharing_level == IntelligenceSharingLevel.FULL:
            return (
                source.trust_level == TrustLevel.VERIFIED and
                target.trust_level == TrustLevel.VERIFIED
            )
        
        if sharing_level == IntelligenceSharingLevel.ANONYMIZED:
            return (
                source.trust_level in [TrustLevel.VERIFIED, TrustLevel.TRUSTED] and
                target.trust_level in [TrustLevel.VERIFIED, TrustLevel.TRUSTED, TrustLevel.PROVISIONAL]
            )
        
        return True


# Singleton instance
_hub: Optional[FederatedIntelligenceHub] = None


def get_federated_intelligence_hub() -> FederatedIntelligenceHub:
    """Get the global hub instance."""
    global _hub
    if _hub is None:
        _hub = FederatedIntelligenceHub()
    return _hub


def reset_federated_intelligence_hub() -> None:
    """Reset the global hub."""
    global _hub
    _hub = None