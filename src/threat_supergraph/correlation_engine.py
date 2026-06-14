"""
Cross-Domain Correlation Engine
Correlates entities and events across fraud, cyber, AML domains.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from .models import ConfidenceLevel, EntityType, RelationshipType


class CrossDomainCorrelationEngine:
    """Engine for correlating across security domains."""
    
    def __init__(self):
        self._correlations: Dict[str, List[Dict[str, Any]]] = {}
        self._correlation_rules: List[Dict[str, Any]] = []
        self._domain_mappings: Dict[str, str] = {}
        self._init_default_mappings()
    
    def _init_default_mappings(self):
        """Initialize default domain mappings."""
        self._domain_mappings = {
            "fraud": "FRAUD_ENTITY",
            "cyber": "THREAT_ACTOR",
            "aml": "MULE_ACCOUNT",
            "threat": "CAMPAIGN",
            "device": "DEVICE",
            "network": "INFRASTRUCTURE",
        }
    
    def correlate(
        self,
        source_domain: str,
        target_domain: str,
        source_id: str,
        target_id: str,
        correlation_type: str,
        confidence: ConfidenceLevel = ConfidenceLevel.POSSIBLE,
        evidence: Optional[List[str]] = None,
    ) -> str:
        """Create a cross-domain correlation."""
        correlation_id = str(uuid4())
        
        correlation = {
            "correlation_id": correlation_id,
            "source_domain": source_domain,
            "target_domain": target_domain,
            "source_id": source_id,
            "target_id": target_id,
            "correlation_type": correlation_type,
            "confidence": confidence.value,
            "evidence": evidence or [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        
        if correlation_id not in self._correlations:
            self._correlations[correlation_id] = []
        self._correlations[correlation_id].append(correlation)
        
        return correlation_id
    
    def find_correlations(
        self,
        entity_id: str,
        domain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Find all correlations for an entity."""
        results = []
        
        for correlations in self._correlations.values():
            for corr in correlations:
                if corr["source_id"] == entity_id or corr["target_id"] == entity_id:
                    if domain is None or corr["source_domain"] == domain or corr["target_domain"] == domain:
                        results.append(corr)
        
        return results
    
    def detect_patterns(
        self,
        entity_ids: List[str],
    ) -> List[Dict[str, Any]]:
        """Detect correlation patterns across entities."""
        patterns = []
        
        pattern_map: Dict[str, List[str]] = {}
        for eid in entity_ids:
            correlations = self.find_correlations(eid)
            for corr in correlations:
                key = f"{corr['source_domain']}:{corr['target_domain']}"
                if key not in pattern_map:
                    pattern_map[key] = []
                pattern_map[key].append(eid)
        
        for pattern, entities in pattern_map.items():
            if len(entities) > 1:
                patterns.append({
                    "pattern_type": pattern,
                    "entities": entities,
                    "count": len(entities),
                    "confidence": len(entities) / 10,
                })
        
        return patterns
    
    def get_domain_stats(self) -> Dict[str, Any]:
        """Get cross-domain statistics."""
        domain_counts: Dict[str, int] = {}
        
        for correlations in self._correlations.values():
            for corr in correlations:
                domain_counts[corr["source_domain"]] = domain_counts.get(corr["source_domain"], 0) + 1
                domain_counts[corr["target_domain"]] = domain_counts.get(corr["target_domain"], 0) + 1
        
        return {
            "total_correlations": sum(len(c) for c in self._correlations.values()),
            "by_domain": domain_counts,
            "pattern_count": len(self._correlation_rules),
        }


def get_correlation_engine() -> CrossDomainCorrelationEngine:
    """Get the global correlation engine instance."""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CrossDomainCorrelationEngine()
    return _correlation_engine


_correlation_engine: Optional[CrossDomainCorrelationEngine] = None