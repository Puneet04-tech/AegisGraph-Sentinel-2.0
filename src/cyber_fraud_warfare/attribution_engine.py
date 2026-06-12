"""
Campaign Attribution Engine for Cyber-Fraud Warfare.

Attributes campaigns to threat actors and analyzes campaign patterns.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
import threading
import hashlib


@dataclass
class AttributionResult:
    """Campaign attribution result."""
    campaign_id: str
    primary_actor_id: Optional[str]
    confidence: str
    evidence: List[Dict[str, Any]]
    alternative_hypotheses: List[Dict[str, Any]]


class CampaignAttributionEngine:
    """Attributes campaigns to threat actors.
    
    Uses evidence analysis and pattern matching to attribute campaigns.
    """

    def __init__(self, store: Any):
        """Initialize the campaign attribution engine.
        
        Args:
            store: Warfare store instance
        """
        self.store = store
        self._attribution_rules: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def add_attribution_rule(
        self,
        rule_name: str,
        rule_conditions: Dict[str, Any],
        suggested_actor_id: str,
        confidence_boost: float = 0.1,
    ) -> None:
        """Add an attribution rule.
        
        Args:
            rule_name: Name of the rule
            rule_conditions: Conditions for the rule
            suggested_actor_id: Actor ID to suggest if rule matches
            confidence_boost: Confidence boost when rule matches
        """
        with self._lock:
            self._attribution_rules.append({
                "name": rule_name,
                "conditions": rule_conditions,
                "actor_id": suggested_actor_id,
                "confidence_boost": confidence_boost,
            })

    def attribute_campaign(self, campaign_id: str) -> AttributionResult:
        """Attribute a campaign to threat actors.
        
        Args:
            campaign_id: Campaign ID to attribute
            
        Returns:
            Attribution result
        """
        campaign = self.store.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign {campaign_id} not found")
        
        # Check existing attribution
        existing = self.store.get_attribution_for_campaign(campaign_id)
        if existing:
            return AttributionResult(
                campaign_id=campaign_id,
                primary_actor_id=existing.get("primary_actor_id"),
                confidence=existing.get("confidence", "LOW"),
                evidence=[existing.get("evidence_summary", "")],
                alternative_hypotheses=existing.get("alternative_hypotheses", []),
            )
        
        # Perform new attribution
        evidence = []
        actor_scores: Dict[str, float] = {}
        
        # Analyze indicators
        indicators = campaign.get("indicators", [])
        for indicator in indicators:
            actor_matches = self._match_indicator_to_actors(indicator)
            for actor_id, match_score in actor_matches.items():
                actor_scores[actor_id] = actor_scores.get(actor_id, 0) + match_score
        
        # Analyze TTPs
        campaign_ttps = set(campaign.get("ttps", []))
        for actor_id in self.store.threat_actors:
            actor = self.store.get_threat_actor(actor_id)
            if not actor:
                continue
            
            actor_ttps = set()
            for ttp in actor.get("ttps", []):
                if isinstance(ttp, dict):
                    actor_ttps.add(ttp.get("id", ""))
                else:
                    actor_ttps.add(str(ttp))
            
            overlap = campaign_ttps & actor_ttps
            if overlap:
                actor_scores[actor_id] = actor_scores.get(actor_id, 0) + len(overlap) * 0.2
        
        # Apply attribution rules
        for rule in self._attribution_rules:
            if self._check_rule_conditions(rule["conditions"], campaign):
                actor_scores[rule["actor_id"]] = actor_scores.get(rule["actor_id"], 0) + rule["confidence_boost"]
                evidence.append(f"Rule '{rule['name']}' matched")
        
        # Analyze target patterns
        target_sectors = set(campaign.get("target_sectors", []))
        target_regions = set(campaign.get("target_regions", []))
        
        for actor_id, actor in self.store.threat_actors.items():
            actor_targets = set(actor.get("primary_targets", []))
            if target_sectors & actor_targets:
                actor_scores[actor_id] = actor_scores.get(actor_id, 0) + 0.3
        
        # Determine best match
        if not actor_scores:
            return AttributionResult(
                campaign_id=campaign_id,
                primary_actor_id=None,
                confidence="UNATTRIBUTED",
                evidence=evidence,
                alternative_hypotheses=[],
            )
        
        sorted_actors = sorted(actor_scores.items(), key=lambda x: x[1], reverse=True)
        primary_actor_id = sorted_actors[0][0]
        primary_score = sorted_actors[0][1]
        
        # Calculate confidence
        if primary_score >= 0.8:
            confidence = "HIGH"
        elif primary_score >= 0.5:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        # Generate alternative hypotheses
        alternatives = []
        for actor_id, score in sorted_actors[1:4]:
            if score >= primary_score * 0.5:
                alternatives.append({
                    "actor_id": actor_id,
                    "actor_name": self.store.get_threat_actor(actor_id).get("name", ""),
                    "score": score,
                    "reason": "TTP overlap or indicator match",
                })
        
        # Store attribution
        attribution = {
            "attribution_id": str(hashlib.md5(f"{campaign_id}{datetime.now(timezone.utc)}".encode()).hexdigest()[:16]),
            "campaign_id": campaign_id,
            "primary_actor_id": primary_actor_id,
            "secondary_actor_ids": [a[0] for a in sorted_actors[1:3]],
            "confidence": confidence,
            "evidence_types": ["indicators", "ttps", "target_patterns"],
            "evidence_summary": "; ".join(evidence[:5]) if evidence else "Pattern-based attribution",
            "alternative_hypotheses": alternatives,
            "attribution_method": "MULTI_FACTOR_ANALYSIS",
        }
        
        self.store.add_attribution(attribution)
        
        return AttributionResult(
            campaign_id=campaign_id,
            primary_actor_id=primary_actor_id,
            confidence=confidence,
            evidence=evidence,
            alternative_hypotheses=alternatives,
        )

    def _match_indicator_to_actors(self, indicator: Dict[str, Any]) -> Dict[str, float]:
        """Match an indicator to possible threat actors.
        
        Args:
            indicator: Indicator data
            
        Returns:
            Dict of actor_id -> match score
        """
        scores = {}
        indicator_type = indicator.get("type", "")
        indicator_value = indicator.get("value", "")
        
        for actor_id, actor in self.store.threat_actors.items():
            # Check actor's historical indicators (would be stored in metadata in production)
            actor_indicators = actor.get("metadata", {}).get("known_indicators", [])
            
            for actor_ind in actor_indicators:
                if actor_ind.get("value") == indicator_value:
                    scores[actor_id] = scores.get(actor_id, 0) + 0.5
        
        return scores

    def _check_rule_conditions(self, conditions: Dict[str, Any], campaign: Dict[str, Any]) -> bool:
        """Check if campaign matches rule conditions.
        
        Args:
            conditions: Rule conditions
            campaign: Campaign data
            
        Returns:
            True if conditions match
        """
        for key, expected in conditions.items():
            actual = campaign.get(key)
            if isinstance(expected, list):
                if not any(e in actual for e in expected):
                    return False
            elif actual != expected:
                return False
        return True

    def get_campaign_cluster(self, campaign_id: str) -> List[str]:
        """Find campaigns that may be part of the same operation.
        
        Args:
            campaign_id: Campaign ID
            
        Returns:
            List of related campaign IDs
        """
        campaign = self.store.get_campaign(campaign_id)
        if not campaign:
            return []
        
        related = [campaign_id]
        
        # Find by shared threat actors
        campaign_actors = set(campaign.get("threat_actor_ids", []))
        for other_campaign in self.store.campaigns.values():
            if other_campaign.get("campaign_id") == campaign_id:
                continue
            
            other_actors = set(other_campaign.get("threat_actor_ids", []))
            if campaign_actors & other_actors:
                related.append(other_campaign.get("campaign_id"))
        
        # Find by overlapping targets
        target_sectors = set(campaign.get("target_sectors", []))
        target_regions = set(campaign.get("target_regions", []))
        
        for other_campaign in self.store.campaigns.values():
            if other_campaign.get("campaign_id") in related:
                continue
            
            other_sectors = set(other_campaign.get("target_sectors", []))
            other_regions = set(other_campaign.get("target_regions", []))
            
            if (target_sectors & other_sectors) and (target_regions & other_regions):
                # Check timing
                start = campaign.get("start_date")
                other_start = other_campaign.get("start_date")
                if start and other_start:
                    if isinstance(start, str):
                        start = datetime.fromisoformat(start.replace("Z", "+00:00"))
                    if isinstance(other_start, str):
                        other_start = datetime.fromisoformat(other_start.replace("Z", "+00:00"))
                    
                    if abs((start - other_start).days) <= 30:
                        related.append(other_campaign.get("campaign_id"))
        
        return list(set(related))

    def predict_campaign_evolution(self, campaign_id: str) -> Dict[str, Any]:
        """Predict how a campaign will evolve.
        
        Args:
            campaign_id: Campaign ID
            
        Returns:
            Prediction data
        """
        campaign = self.store.get_campaign(campaign_id)
        if not campaign:
            return {"error": "Campaign not found"}
        
        status = campaign.get("status", "EMERGING")
        
        # Predict next status
        status_transitions = {
            "EMERGING": ("ACTIVE", 7),
            "ACTIVE": ("PEAKED", 14),
            "PEAKED": ("DECLINING", 7),
            "DECLINING": ("DORMANT", 30),
        }
        
        if status in status_transitions:
            next_status, estimated_days = status_transitions[status]
        else:
            next_status, estimated_days = status, 30
        
        # Predict scale changes
        scale_factors = campaign.get("estimated_victims", 0)
        scale_trend = "STABLE"
        if scale_factors > 10000:
            scale_trend = "EXPANDING"
        elif scale_factors < 100:
            scale_trend = "CONTRACTING"
        
        return {
            "campaign_id": campaign_id,
            "current_status": status,
            "predicted_next_status": next_status,
            "estimated_days_to_transition": estimated_days,
            "scale_trend": scale_trend,
            "confidence": "MEDIUM",
            "factors": [
                "Historical patterns for similar campaigns",
                "Current campaign characteristics",
            ],
        }


def get_attribution_engine() -> CampaignAttributionEngine:
    """Get the global attribution engine instance."""
    from .store import get_warfare_store
    store = get_warfare_store()
    return CampaignAttributionEngine(store)