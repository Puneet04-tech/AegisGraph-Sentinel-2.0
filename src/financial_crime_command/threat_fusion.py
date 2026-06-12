"""
Threat Fusion Engine.

Fuses threat intelligence from multiple sources.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timezone
from typing import Any, Dict, List, Optional, Set
import uuid

from .models import ThreatIndicator, ThreatLevel
from .store import FinancialCrimeStore, get_financial_crime_store


@dataclass
class ThreatCluster:
    """Cluster of related threats."""
    cluster_id: str
    threat_level: ThreatLevel
    threats: List[ThreatIndicator] = field(default_factory=list)
    shared_indicators: List[str] = field(default_factory=list)
    confidence: float = 0.5
    attribution: Optional[str] = None


@dataclass
class FusionResult:
    """Result of threat fusion analysis."""
    threat_clusters: List[ThreatCluster]
    high_priority_threats: List[ThreatIndicator]
    threat_actors: List[Dict[str, Any]]
    recommended_actions: List[str]


class ThreatFusionEngine:
    """Engine for fusing threat intelligence."""

    def __init__(self, store: Optional[FinancialCrimeStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_financial_crime_store()

    async def fuse_threats(self) -> FusionResult:
        """Fuse threats from all sources."""
        threats = list(self.store._threats.values())
        
        clusters = self._identify_clusters(threats)
        high_priority = self._get_high_priority_threats(threats)
        actors = self._identify_threat_actors(clusters)
        actions = self._generate_actions(clusters, high_priority)
        
        return FusionResult(
            threat_clusters=clusters,
            high_priority_threats=high_priority,
            threat_actors=actors,
            recommended_actions=actions,
        )

    def _identify_clusters(self, threats: List[ThreatIndicator]) -> List[ThreatCluster]:
        """Identify clusters of related threats."""
        clusters: List[ThreatCluster] = []
        assigned: Set[str] = set()
        
        for threat in threats:
            if threat.indicator_id in assigned:
                continue
            
            cluster_threats = [threat]
            assigned.add(threat.indicator_id)
            
            for other in threats:
                if other.indicator_id in assigned:
                    continue
                if self._is_related(threat, other):
                    cluster_threats.append(other)
                    assigned.add(other.indicator_id)
            
            if len(cluster_threats) >= 2:
                threat_level = self._assess_cluster_level(cluster_threats)
                cluster = ThreatCluster(
                    cluster_id=str(uuid.uuid4()),
                    threat_level=threat_level,
                    threats=cluster_threats,
                    shared_indicators=self._get_shared_indicators(cluster_threats),
                    confidence=min(0.9, 0.5 + len(cluster_threats) * 0.1),
                )
                clusters.append(cluster)
        
        return sorted(clusters, key=lambda c: c.threat_level.value)

    def _is_related(self, t1: ThreatIndicator, t2: ThreatIndicator) -> bool:
        """Check if two threats are related."""
        if t1.indicator_type == t2.indicator_type:
            return True
        if set(t1.tags) & set(t2.tags):
            return True
        if abs((t1.last_seen - t2.last_seen).total_seconds()) < 3600:
            return True
        return False

    def _assess_cluster_level(self, threats: List[ThreatIndicator]) -> ThreatLevel:
        """Assess threat level for a cluster."""
        max_confidence = max(t.confidence for t in threats)
        if max_confidence > 0.9:
            return ThreatLevel.SEVERE
        elif max_confidence > 0.7:
            return ThreatLevel.CRITICAL
        elif max_confidence > 0.5:
            return ThreatLevel.HIGH
        elif max_confidence > 0.3:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW

    def _get_shared_indicators(self, threats: List[ThreatIndicator]) -> List[str]:
        """Get shared indicators across threats."""
        all_tags: Set[str] = set()
        for threat in threats:
            all_tags.update(threat.tags)
        return list(all_tags)

    def _get_high_priority_threats(
        self,
        threats: List[ThreatIndicator],
        threshold: float = 0.7,
    ) -> List[ThreatIndicator]:
        """Get high priority threats."""
        return sorted(
            [t for t in threats if t.confidence >= threshold],
            key=lambda t: t.confidence,
            reverse=True,
        )[:20]

    def _identify_threat_actors(
        self,
        clusters: List[ThreatCluster],
    ) -> List[Dict[str, Any]]:
        """Identify potential threat actors."""
        actors = []
        for cluster in clusters:
            if cluster.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.SEVERE]:
                actors.append({
                    "actor_id": str(uuid.uuid4()),
                    "confidence": cluster.confidence,
                    "associated_indicators": len(cluster.threats),
                    "threat_level": cluster.threat_level.value,
                    "indicator_types": list(set(t.indicator_type for t in cluster.threats)),
                })
        return actors

    def _generate_actions(
        self,
        clusters: List[ThreatCluster],
        high_priority: List[ThreatIndicator],
    ) -> List[str]:
        """Generate recommended actions."""
        actions = []
        if any(c.threat_level == ThreatLevel.SEVERE for c in clusters):
            actions.append("CRITICAL: Immediate response required for severe threats")
        if len(high_priority) > 5:
            actions.append("Multiple high-confidence threats detected - batch investigation")
        for cluster in clusters:
            if cluster.threat_level == ThreatLevel.CRITICAL:
                actions.append(f"Investigate threat cluster {cluster.cluster_id[:8]}")
        if not actions:
            actions.append("Continue standard threat monitoring")
        return actions

    def add_threat(
        self,
        indicator_type: str,
        value: Any,
        confidence: float,
        source: str,
        tags: Optional[List[str]] = None,
    ) -> ThreatIndicator:
        """Add a new threat indicator."""
        threat = ThreatIndicator(
            indicator_id=str(uuid.uuid4()),
            indicator_type=indicator_type,
            value=value,
            confidence=confidence,
            source=source,
            tags=tags or [],
        )
        self.store.store_threat(threat)
        return threat

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get threat summary for dashboard."""
        threats = list(self.store._threats.values())
        by_type: Dict[str, int] = {}
        by_level: Dict[str, int] = {}
        
        for threat in threats:
            by_type[threat.indicator_type] = by_type.get(threat.indicator_type, 0) + 1
        
        clusters = self._identify_clusters(threats)
        for level in ThreatLevel:
            by_level[level.value] = len([c for c in clusters if c.threat_level == level])
        
        return {
            "total_threats": len(threats),
            "threats_by_type": by_type,
            "threats_by_level": by_level,
            "active_clusters": len(clusters),
            "high_priority_count": len(self._get_high_priority_threats(threats)),
        }


# Singleton instance
_engine: Optional[ThreatFusionEngine] = None


def get_threat_fusion_engine() -> ThreatFusionEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = ThreatFusionEngine()
    return _engine


def reset_threat_fusion_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None