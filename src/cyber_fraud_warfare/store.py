"""
Storage layer for Cyber-Fraud Warfare Intelligence Platform.

Provides persistent storage for threat actors, campaigns, and relationships.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import threading
import uuid


@dataclass
class WarfareStore:
    """Central storage for cyber-fraud warfare data.
    
    Thread-safe in-memory storage with persistence capabilities.
    """
    threat_actors: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    campaigns: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    attributions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    threat_profiles: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    attack_patterns: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    risk_assessments: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    threat_relationships: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add_threat_actor(self, actor: Dict[str, Any]) -> str:
        """Add a new threat actor."""
        with self._lock:
            actor_id = actor.get("actor_id", str(uuid.uuid4()))
            actor["actor_id"] = actor_id
            self.threat_actors[actor_id] = actor
            return actor_id

    def get_threat_actor(self, actor_id: str) -> Optional[Dict[str, Any]]:
        """Get a threat actor by ID."""
        return self.threat_actors.get(actor_id)

    def list_threat_actors(
        self,
        actor_type: Optional[str] = None,
        sponsor: Optional[str] = None,
        threat_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List threat actors with optional filtering."""
        results = list(self.threat_actors.values())
        if actor_type:
            results = [a for a in results if a.get("type") == actor_type]
        if sponsor:
            results = [a for a in results if a.get("sponsor") == sponsor]
        if threat_level:
            results = [a for a in results if a.get("threat_level") == threat_level]
        return results

    def add_campaign(self, campaign: Dict[str, Any]) -> str:
        """Add a new campaign."""
        with self._lock:
            campaign_id = campaign.get("campaign_id", str(uuid.uuid4()))
            campaign["campaign_id"] = campaign_id
            self.campaigns[campaign_id] = campaign
            return campaign_id

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get a campaign by ID."""
        return self.campaigns.get(campaign_id)

    def list_campaigns(
        self,
        status: Optional[str] = None,
        target_sector: Optional[str] = None,
        threat_actor_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List campaigns with optional filtering."""
        results = list(self.campaigns.values())
        if status:
            results = [c for c in results if c.get("status") == status]
        if target_sector:
            results = [c for c in results if target_sector in c.get("target_sectors", [])]
        if threat_actor_id:
            results = [c for c in results if threat_actor_id in c.get("threat_actor_ids", [])]
        return sorted(results, key=lambda x: x.get("discovered_date", ""), reverse=True)

    def add_attribution(self, attribution: Dict[str, Any]) -> str:
        """Add attribution data."""
        with self._lock:
            attr_id = attribution.get("attribution_id", str(uuid.uuid4()))
            attribution["attribution_id"] = attr_id
            self.attributions[attr_id] = attribution
            return attr_id

    def get_attribution(self, attribution_id: str) -> Optional[Dict[str, Any]]:
        """Get attribution by ID."""
        return self.attributions.get(attribution_id)

    def get_attribution_for_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get attribution for a campaign."""
        for attr in self.attributions.values():
            if attr.get("campaign_id") == campaign_id:
                return attr
        return None

    def add_attack_pattern(self, pattern: Dict[str, Any]) -> str:
        """Add an attack pattern."""
        with self._lock:
            pattern_id = pattern.get("pattern_id", str(uuid.uuid4()))
            pattern["pattern_id"] = pattern_id
            self.attack_patterns[pattern_id] = pattern
            return pattern_id

    def get_attack_pattern(self, pattern_id: str) -> Optional[Dict[str, Any]]:
        """Get attack pattern by ID."""
        return self.attack_patterns.get(pattern_id)

    def list_attack_patterns(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """List attack patterns with optional filtering."""
        results = list(self.attack_patterns.values())
        if category:
            results = [p for p in results if p.get("category") == category]
        return results

    def add_risk_assessment(self, assessment: Dict[str, Any]) -> str:
        """Add a risk assessment."""
        with self._lock:
            assess_id = assessment.get("assessment_id", str(uuid.uuid4()))
            assessment["assessment_id"] = assess_id
            self.risk_assessments[assess_id] = assessment
            return assess_id

    def get_risk_assessment(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Get risk assessment by ID."""
        return self.risk_assessments.get(assessment_id)

    def get_latest_assessment(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get latest assessment for an entity."""
        assessments = [
            a for a in self.risk_assessments.values()
            if a.get("entity_id") == entity_id
        ]
        if not assessments:
            return None
        return max(assessments, key=lambda x: x.get("assessment_date", ""))

    def add_threat_relationship(self, relationship: Dict[str, Any]) -> str:
        """Add a threat relationship."""
        with self._lock:
            rel_id = relationship.get("relationship_id", str(uuid.uuid4()))
            relationship["relationship_id"] = rel_id
            self.threat_relationships[rel_id] = relationship
            return rel_id

    def get_relationships_for_entity(
        self,
        entity_id: str,
        relationship_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get relationships for an entity."""
        results = [
            r for r in self.threat_relationships.values()
            if r.get("source_id") == entity_id or r.get("target_id") == entity_id
        ]
        if relationship_type:
            results = [r for r in results if r.get("relationship_type") == relationship_type]
        return results

    def add_threat_profile(self, profile: Dict[str, Any]) -> str:
        """Add a threat profile."""
        with self._lock:
            profile_id = profile.get("profile_id", str(uuid.uuid4()))
            profile["profile_id"] = profile_id
            self.threat_profiles[profile_id] = profile
            return profile_id

    def get_threat_profile(self, profile_id: str) -> Optional[Dict[str, Any]]:
        """Get threat profile by ID."""
        return self.threat_profiles.get(profile_id)

    def get_threat_profile_for_entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get threat profile for an entity."""
        for profile in self.threat_profiles.values():
            if profile.get("entity_id") == entity_id:
                return profile
        return None

    def get_warfare_stats(self) -> Dict[str, Any]:
        """Get warfare intelligence statistics."""
        # Actor stats by type
        actor_types = {}
        for actor in self.threat_actors.values():
            atype = actor.get("type", "UNKNOWN")
            actor_types[atype] = actor_types.get(atype, 0) + 1
        
        # Campaign stats by status
        campaign_status = {}
        for campaign in self.campaigns.values():
            status = campaign.get("status", "UNKNOWN")
            campaign_status[status] = campaign_status.get(status, 0) + 1
        
        # Active campaigns count
        active_campaigns = len([
            c for c in self.campaigns.values()
            if c.get("status") in ("EMERGING", "ACTIVE", "PEAKED")
        ])
        
        # High threat actors
        high_threat_actors = len([
            a for a in self.threat_actors.values()
            if a.get("threat_level") in ("CRITICAL", "HIGH")
        ])
        
        return {
            "total_threat_actors": len(self.threat_actors),
            "actors_by_type": actor_types,
            "high_threat_actors": high_threat_actors,
            "total_campaigns": len(self.campaigns),
            "active_campaigns": active_campaigns,
            "campaigns_by_status": campaign_status,
            "total_attack_patterns": len(self.attack_patterns),
            "total_risk_assessments": len(self.risk_assessments),
            "total_relationships": len(self.threat_relationships),
        }


# Singleton instance
_store: Optional[WarfareStore] = None


def get_warfare_store() -> WarfareStore:
    """Get the global warfare store instance."""
    global _store
    if _store is None:
        _store = WarfareStore()
    return _store