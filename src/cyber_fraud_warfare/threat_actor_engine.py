"""
Threat Actor Intelligence Engine for Cyber-Fraud Warfare.

Analyzes threat actors, tracks activities, and maintains actor profiles.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
import threading
import hashlib


@dataclass
class ActorAnalysis:
    """Threat actor analysis result."""
    actor_id: str
    analysis_date: datetime
    threat_score: float
    activity_level: str
    associated_campaigns: List[str]
    detected_ttps: List[str]
    risk_factors: List[str]
    recommended_posture: str


class ThreatActorIntelligenceEngine:
    """Analyzes threat actors and maintains actor intelligence.
    
    Tracks actor activities, capabilities, and associations.
    """

    def __init__(self, store: Any):
        """Initialize the threat actor intelligence engine.
        
        Args:
            store: Warfare store instance
        """
        self.store = store
        self._activity_timeline: Dict[str, List[Dict[str, Any]]] = {}
        self._ttp_mappings: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

    def analyze_actor(self, actor_id: str) -> ActorAnalysis:
        """Perform comprehensive analysis of a threat actor.
        
        Args:
            actor_id: Threat actor ID
            
        Returns:
            Actor analysis result
        """
        actor = self.store.get_threat_actor(actor_id)
        if not actor:
            raise ValueError(f"Threat actor {actor_id} not found")
        
        # Calculate threat score
        threat_score = self._calculate_threat_score(actor)
        
        # Determine activity level
        activity_level = self._determine_activity_level(actor)
        
        # Find associated campaigns
        campaigns = self._find_associated_campaigns(actor_id)
        
        # Detect TTPs
        detected_ttps = self._detect_ttps(actor_id)
        
        # Identify risk factors
        risk_factors = self._identify_risk_factors(actor, campaigns)
        
        # Generate recommended posture
        recommended_posture = self._generate_posture_recommendation(threat_score, activity_level)
        
        return ActorAnalysis(
            actor_id=actor_id,
            analysis_date=datetime.now(timezone.utc),
            threat_score=threat_score,
            activity_level=activity_level,
            associated_campaigns=campaigns,
            detected_ttps=detected_ttps,
            risk_factors=risk_factors,
            recommended_posture=recommended_posture,
        )

    def _calculate_threat_score(self, actor: Dict[str, Any]) -> float:
        """Calculate overall threat score for an actor."""
        score = 0.0
        
        # Base score by type
        type_scores = {
            "NATION_STATE": 90,
            "CYBERCRIME_ORG": 80,
            "HACKTIVIST": 40,
            "INSIDER": 70,
            "TERRORIST": 85,
            "SCRIPT_KIDDIE": 20,
            "UNKNOWN": 30,
        }
        score += type_scores.get(actor.get("type", "UNKNOWN"), 30)
        
        # Sponsorship multiplier
        sponsor_multipliers = {
            "STATE_SPONSORED": 1.5,
            "STATE_AFFILIATED": 1.3,
            "CRIMINALLY_MOTIVATED": 1.2,
            "FINANCIALLY_MOTIVATED": 1.1,
            "IDEOLOGICALLY_MOTIVATED": 1.0,
            "UNSPONSORED": 0.8,
        }
        sponsor = actor.get("sponsor", "UNSPONSORED")
        score *= sponsor_multipliers.get(sponsor, 1.0)
        
        # Capability bonus
        capabilities = actor.get("capabilities", [])
        score += min(10, len(capabilities) * 2)
        
        # Activity bonus
        confirmed = actor.get("confirmed_attacks", 0)
        suspected = actor.get("suspected_attacks", 0)
        score += min(20, confirmed * 2 + suspected * 0.5)
        
        return min(100, max(0, score))

    def _determine_activity_level(self, actor: Dict[str, Any]) -> str:
        """Determine actor activity level."""
        last_activity = actor.get("last_activity")
        if not last_activity:
            return "DORMANT"
        
        if isinstance(last_activity, str):
            last_activity = datetime.fromisoformat(last_activity.replace("Z", "+00:00"))
        
        days_since = (datetime.now(timezone.utc) - last_activity).days
        
        if days_since <= 7:
            return "VERY_ACTIVE"
        elif days_since <= 30:
            return "ACTIVE"
        elif days_since <= 90:
            return "MODERATE"
        elif days_since <= 180:
            return "LOW"
        return "DORMANT"

    def _find_associated_campaigns(self, actor_id: str) -> List[str]:
        """Find campaigns associated with an actor."""
        campaigns = []
        for campaign in self.store.campaigns.values():
            if actor_id in campaign.get("threat_actor_ids", []):
                campaigns.append(campaign.get("campaign_id"))
        return campaigns

    def _detect_ttps(self, actor_id: str) -> List[str]:
        """Detect TTPs used by an actor."""
        ttps = []
        
        # From actor profile
        actor = self.store.get_threat_actor(actor_id)
        if actor:
            for ttp in actor.get("ttps", []):
                if isinstance(ttp, dict):
                    ttps.append(ttp.get("id", ""))
                else:
                    ttps.append(str(ttp))
        
        # From associated campaigns
        for campaign_id in self._find_associated_campaigns(actor_id):
            campaign = self.store.get_campaign(campaign_id)
            if campaign:
                ttps.extend(campaign.get("ttps", []))
        
        return list(set(ttps))

    def _identify_risk_factors(self, actor: Dict, campaigns: List[str]) -> List[str]:
        """Identify risk factors from actor and campaigns."""
        factors = []
        
        if actor.get("type") == "NATION_STATE":
            factors.append("Nation-state actor with significant resources")
        
        if actor.get("sponsor") == "STATE_SPONSORED":
            factors.append("State-sponsored operations with government backing")
        
        if actor.get("confirmed_attacks", 0) > 10:
            factors.append("History of successful attacks")
        
        active_campaigns = len([
            c for c in campaigns
            if self.store.get_campaign(c).get("status") == "ACTIVE"
        ])
        if active_campaigns > 0:
            factors.append(f"{active_campaigns} active campaigns")
        
        return factors

    def _generate_posture_recommendation(self, threat_score: float, activity_level: str) -> str:
        """Generate recommended defensive posture."""
        if threat_score >= 80 and activity_level in ("VERY_ACTIVE", "ACTIVE"):
            return "CRITICAL_ALERT"
        elif threat_score >= 60:
            return "HIGH_ALERT"
        elif threat_score >= 40:
            return "MODERATE_ALERT"
        return "STANDARD"

    def track_activity(self, actor_id: str, activity: Dict[str, Any]) -> None:
        """Track a new activity for an actor.
        
        Args:
            actor_id: Threat actor ID
            activity: Activity data
        """
        with self._lock:
            if actor_id not in self._activity_timeline:
                self._activity_timeline[actor_id] = []
            
            self._activity_timeline[actor_id].append({
                **activity,
                "timestamp": datetime.now(timezone.utc),
            })
            
            # Update actor's last activity
            actor = self.store.get_threat_actor(actor_id)
            if actor:
                actor["last_activity"] = datetime.now(timezone.utc)

    def get_activity_timeline(
        self,
        actor_id: str,
        days: int = 90,
    ) -> List[Dict[str, Any]]:
        """Get activity timeline for an actor.
        
        Args:
            actor_id: Threat actor ID
            days: Number of days to look back
            
        Returns:
            Activity timeline
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        timeline = self._activity_timeline.get(actor_id, [])
        
        return [
            {
                **activity,
                "timestamp": activity["timestamp"].isoformat(),
            }
            for activity in timeline
            if activity["timestamp"] >= cutoff
        ]

    def identify_related_actors(self, actor_id: str) -> List[Dict[str, Any]]:
        """Identify actors related to the given actor.
        
        Args:
            actor_id: Threat actor ID
            
        Returns:
            List of related actors
        """
        actor = self.store.get_threat_actor(actor_id)
        if not actor:
            return []
        
        related_ids = set(actor.get("associated_actor_ids", []))
        
        # Also check relationships
        for rel in self.store.get_relationships_for_entity(actor_id):
            if rel.get("source_id") == actor_id:
                related_ids.add(rel.get("target_id"))
            else:
                related_ids.add(rel.get("source_id"))
        
        # Also check shared campaigns
        actor_campaigns = set(self._find_associated_campaigns(actor_id))
        for campaign_id in actor_campaigns:
            campaign = self.store.get_campaign(campaign_id)
            if campaign:
                for other_actor_id in campaign.get("threat_actor_ids", []):
                    if other_actor_id != actor_id:
                        related_ids.add(other_actor_id)
        
        return [
            self.store.get_threat_actor(aid)
            for aid in related_ids
            if self.store.get_threat_actor(aid)
        ]

    def compare_actors(self, actor_id_1: str, actor_id_2: str) -> Dict[str, Any]:
        """Compare two threat actors.
        
        Args:
            actor_id_1: First actor ID
            actor_id_2: Second actor ID
            
        Returns:
            Comparison results
        """
        actor1 = self.store.get_threat_actor(actor_id_1)
        actor2 = self.store.get_threat_actor(actor_id_2)
        
        if not actor1 or not actor2:
            return {"error": "One or both actors not found"}
        
        # Find common TTPs
        ttps1 = set(self._detect_ttps(actor_id_1))
        ttps2 = set(self._detect_ttps(actor_id_2))
        common_ttps = ttps1 & ttps2
        
        # Find shared campaigns
        campaigns1 = set(self._find_associated_campaigns(actor_id_1))
        campaigns2 = set(self._find_associated_campaigns(actor_id_2))
        shared_campaigns = campaigns1 & campaigns2
        
        return {
            "actor1": {
                "id": actor_id_1,
                "name": actor1.get("name"),
                "threat_score": self._calculate_threat_score(actor1),
            },
            "actor2": {
                "id": actor_id_2,
                "name": actor2.get("name"),
                "threat_score": self._calculate_threat_score(actor2),
            },
            "common_ttps": list(common_ttps),
            "shared_campaigns": list(shared_campaigns),
            "similarity_score": len(common_ttps) / max(1, len(ttps1 | ttps2)),
        }


def get_threat_actor_engine() -> ThreatActorIntelligenceEngine:
    """Get the global threat actor engine instance."""
    from .store import get_warfare_store
    store = get_warfare_store()
    return ThreatActorIntelligenceEngine(store)