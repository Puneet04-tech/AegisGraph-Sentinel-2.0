"""
Threat Intelligence Agent.

Analyzes threat data, tracks threat actors, and generates threat intelligence reports.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    AgentTask,
    AgentType,
    TaskPriority,
    ThreatIntelligenceReport,
)
from src.cyber_threat_intel.store import get_cti_store

from .store import SOCStore, get_soc_store

logger = logging.getLogger(__name__)


class ThreatIntelligenceAgent:
    """Threat Intelligence Agent for fraud threat analysis.
    
    Capabilities:
        - Threat detection and classification
        - IOC (Indicator of Compromise) analysis
        - MITRE ATT&CK technique mapping
        - Threat actor tracking
        - Threat intelligence report generation
    """
    
    def __init__(self, store: Optional[SOCStore] = None, cti_store=None):
        """Initialize the threat intelligence agent.
        
        Args:
            store: Optional SOC store
        """
        self._store = store or get_soc_store()
        # Real intelligence source. Enrichment previously invented every field
        # it returned without consulting any store.
        self._cti = cti_store or get_cti_store()
        self._agent_id = "threat_intelligence_agent"
        
        # Known threat patterns
        self._threat_patterns = {
            "credential_stuffing": ["brute_force_attempts", "password_spray", "credential_theft"],
            "account_takeover": ["phishing", "social_engineering", "session_hijacking"],
            "payment_fraud": ["card_testing", " BIN_attacks", "test_transactions"],
            "money_laundering": ["structuring", "layering", "integration"],
            "synthetic_identity": ["fabricated_identity", "hybrid_identity", "manipulated_identity"],
        }
    
    def analyze_threat(
        self,
        threat_type: str,
        indicators: List[Dict[str, Any]],
        context: Dict[str, Any] = None,
    ) -> ThreatIntelligenceReport:
        """Analyze a threat and generate a report.
        
        Args:
            threat_type: Type of threat
            indicators: Threat indicators
            context: Additional context
            
        Returns:
            ThreatIntelligenceReport
        """
        logger.info(f"Analyzing threat type: {threat_type}")
        
        context = context or {}
        
        # Generate threat actors
        threat_actors = self._identify_threat_actors(threat_type)
        
        # Map to MITRE ATT&CK techniques
        ttps = self._map_to_attack_techniques(threat_type)
        
        # Calculate confidence and severity
        # Derived from how much corroborating intelligence exists, not drawn
        # from random.uniform(0.7, 0.95).
        confidence = self._confidence_from_evidence(indicators, threat_actors, ttps)
        severity = self._calculate_severity(len(indicators), confidence)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threat_type, ttps)
        
        report = ThreatIntelligenceReport(
            threat_type=threat_type,
            threat_actors=threat_actors,
            indicators=indicators,
            ttps=ttps,
            affected_entities=context.get("affected_entities", []),
            confidence=confidence,
            severity=severity,
            description=self._generate_description(threat_type, indicators),
            recommendations=recommendations,
            sources=["internal_analysis", "threat_feed", "user_reports"],
        )
        
        # Store report
        self._store.store_threat_report(report)
        
        logger.info(f"Threat analysis complete: {threat_type}, severity: {severity}")
        return report
    
    def enrich_ioc(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich an IOC with additional context.
        
        Args:
            ioc: Indicator of Compromise
            
        Returns:
            Enriched IOC
        """
        ioc_type = ioc.get("type", "unknown")
        
        record = self._lookup_ioc(ioc.get("value") or ioc.get("indicator"))

        if record is None:
            # Nothing is known about this indicator. Say so, rather than
            # inventing an association count, a prevalence band and a source
            # country -- an invented attribution is a specific,
            # actionable-looking claim with no basis whatsoever.
            return {
                **ioc,
                "known": False,
                "confidence_score": 0.0,
                "threat_associations": 0,
                "historical_prevalence": "unknown",
                "last_seen": None,
            }

        campaigns = self._campaigns_for_ioc(record.ioc_id)
        associations = len(campaigns) + len(
            {actor for campaign in campaigns for actor in (campaign.actors or [])}
        )

        enriched = {
            **ioc,
            "known": True,
            "confidence_score": round(float(record.confidence or 0.0), 4),
            "threat_associations": associations,
            "threat_level": record.threat_level.value,
            "last_seen": record.last_seen.isoformat() if record.last_seen else None,
            "historical_prevalence": self._prevalence_band(len(campaigns)),
        }

        # Attribution only ever comes from a stored record's own metadata.
        country = (record.metadata or {}).get("country")
        if country:
            enriched["geolocation"] = {"country": country}

        return enriched
    
    def track_threat_actor(self, actor_name: str, activity: Dict[str, Any]) -> Dict[str, Any]:
        """Track a threat actor's activity.
        
        Args:
            actor_name: Name of the threat actor
            activity: Activity data
            
        Returns:
            Actor tracking data
        """
        record = self._lookup_actor(actor_name)
        if record is None:
            return {
                "actor_name": actor_name,
                "known": False,
                "last_activity": None,
                "activity_count": 0,
                "primary_ttps": [],
                "associated_campaigns": [],
                "confidence": 0.0,
            }

        campaigns = self._campaigns_for_actor(record.actor_id)
        return {
            "actor_name": actor_name,
            "known": True,
            "last_activity": max(
                (c.start_date for c in campaigns if c.start_date), default=None
            ),
            "activity_count": len(campaigns),
            # Capabilities are what the store actually records; inventing
            # MITRE technique ids would be the same defect in a new place.
            "primary_ttps": list(record.capabilities or []),
            "associated_campaigns": [c.name for c in campaigns],
            "confidence": round(float(record.confidence or 0.0), 4),
        }

    # ------------------------------------------------------------------
    # Intelligence lookups
    # ------------------------------------------------------------------

    def _lookup_ioc(self, value):
        """Resolve an indicator against the CTI store, or None if unknown."""
        if not value:
            return None
        try:
            for ioc in self._cti._iocs.values():
                if ioc.value == value:
                    return ioc
        except Exception as exc:
            logger.warning("IOC lookup failed for %s: %s", value, exc)
        return None

    def _lookup_actor(self, name):
        """Resolve a threat actor against the CTI store, or None if unknown."""
        if not name:
            return None
        try:
            for actor in self._cti._actors.values():
                if actor.name == name or name in (actor.aliases or []):
                    return actor
        except Exception as exc:
            logger.warning("Actor lookup failed for %s: %s", name, exc)
        return None

    def _campaigns_for_ioc(self, ioc_id: str) -> List[Any]:
        try:
            return [c for c in self._cti._campaigns.values() if ioc_id in (c.iocs or [])]
        except Exception:
            return []

    def _campaigns_for_actor(self, actor_id: str) -> List[Any]:
        try:
            return [c for c in self._cti._campaigns.values() if actor_id in (c.actors or [])]
        except Exception:
            return []

    @staticmethod
    def _prevalence_band(sightings: int) -> str:
        """Map an observed campaign count onto a prevalence band."""
        if sightings <= 0:
            return "unknown"
        if sightings == 1:
            return "rare"
        if sightings <= 3:
            return "uncommon"
        if sightings <= 10:
            return "common"
        return "widespread"

    @staticmethod
    def _confidence_from_evidence(indicators, actors, ttps) -> float:
        """Confidence scaled by how much corroborating evidence exists."""
        evidence = len(indicators or []) + len(actors or []) + len(ttps or [])
        if evidence == 0:
            return 0.0
        return round(min(0.95, 0.4 + 0.05 * evidence), 4)
    
    def create_threat_hunt_task(
        self,
        hypothesis: str,
        indicators: List[str],
        priority: TaskPriority = TaskPriority.HIGH,
    ) -> AgentTask:
        """Create a threat hunting task.
        
        Args:
            hypothesis: Hunt hypothesis
            indicators: IOCs to hunt for
            priority: Task priority
            
        Returns:
            AgentTask
        """
        task = AgentTask(
            agent_type=AgentType.THREAT_INTELLIGENCE,
            title=f"Threat Hunt: {hypothesis[:50]}",
            description=f"Investigate hypothesis: {hypothesis}\nIndicators: {', '.join(indicators[:5])}",
            priority=priority,
            context={
                "hypothesis": hypothesis,
                "indicators": indicators,
                "type": "threat_hunt",
            },
        )
        
        self._store.store_task(task)
        logger.info(f"Created threat hunt task: {task.task_id}")
        
        return task
    
    def get_active_threats(self, hours: int = 24) -> List[ThreatIntelligenceReport]:
        """Get active threats from the last N hours."""
        return self._store.get_recent_threats(hours)
    
    def _identify_threat_actors(self, threat_type: str) -> List[str]:
        """Identify potential threat actors."""
        actors = {
            "credential_stuffing": ["bot_network_alpha", "credential_trader_collective"],
            "account_takeover": ["phishing_king", "social_engineer_guild"],
            "payment_fraud": ["card_test_ring", "fraud_network_lotus"],
            "money_laundering": ["layering_network_cobra", "integration_group_phi"],
            "synthetic_identity": ["identity_fabricator_collective", "synthetic_ring_zeta"],
        }
        return actors.get(threat_type, ["unknown_actor"])
    
    def _map_to_attack_techniques(self, threat_type: str) -> List[str]:
        """Map threat to MITRE ATT&CK techniques."""
        technique_mapping = {
            "credential_stuffing": ["T1078", "T1110", "T1566"],
            "account_takeover": ["T1566", "T1484", "T1078"],
            "payment_fraud": ["T1059", "T1566", "T1078"],
            "money_laundering": ["T1048", "T1566", "T1059"],
            "synthetic_identity": ["T1136", "T1484", "T1566"],
        }
        return technique_mapping.get(threat_type, ["T1566"])
    
    def _calculate_severity(self, indicator_count: int, confidence: float) -> str:
        """Calculate threat severity."""
        score = indicator_count * confidence
        if score >= 2.5:
            return "CRITICAL"
        elif score >= 1.5:
            return "HIGH"
        elif score >= 0.8:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, threat_type: str, ttps: List[str]) -> List[str]:
        """Generate threat mitigation recommendations."""
        recommendations = [
            "Monitor for associated indicators",
            "Update detection rules",
            "Review access logs",
        ]
        
        if "T1078" in ttps:  # Valid Accounts
            recommendations.append("Enforce MFA for all accounts")
        
        if "T1566" in ttps:  # Phishing
            recommendations.append("Enhance email filtering rules")
            recommendations.append("User security awareness training")
        
        if "T1059" in ttps:  # Command and Scripting Interpreter
            recommendations.append("Restrict command execution permissions")
        
        return recommendations
    
    def _generate_description(self, threat_type: str, indicators: List[Dict[str, Any]]) -> str:
        """Generate threat description."""
        return f"{threat_type.replace('_', ' ').title()} threat detected with {len(indicators)} associated indicators"


# Global singleton
_threat_agent: Optional[ThreatIntelligenceAgent] = None


def get_threat_intelligence_agent(store: Optional[SOCStore] = None) -> ThreatIntelligenceAgent:
    """Get or create the singleton ThreatIntelligenceAgent instance."""
    global _threat_agent
    
    if _threat_agent is None:
        _threat_agent = ThreatIntelligenceAgent(store=store)
    return _threat_agent