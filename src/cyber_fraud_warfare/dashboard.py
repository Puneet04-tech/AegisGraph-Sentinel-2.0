"""
Strategic Threat Dashboard for Cyber-Fraud Warfare.

Provides strategic visibility into threat landscape.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from .models import ThreatActor, Campaign, RiskAssessment


class StrategicThreatDashboard:
    """Strategic threat dashboard service.
    
    Aggregates threat intelligence for executive visibility.
    """

    def __init__(self, store: Any, actor_engine: Any, attribution_engine: Any):
        """Initialize the strategic threat dashboard.
        
        Args:
            store: Warfare store instance
            actor_engine: Threat actor engine instance
            attribution_engine: Attribution engine instance
        """
        self.store = store
        self.actor_engine = actor_engine
        self.attribution_engine = attribution_engine

    def generate_dashboard(self) -> Dict[str, Any]:
        """Generate the strategic threat dashboard.
        
        Returns:
            Dashboard data
        """
        now = datetime.now(timezone.utc)
        
        # Get threat actor summary
        actor_summary = self._get_actor_summary()
        
        # Get campaign summary
        campaign_summary = self._get_campaign_summary()
        
        # Get risk summary
        risk_summary = self._get_risk_summary()
        
        # Get emerging threats
        emerging_threats = self._get_emerging_threats()
        
        # Get threat trends
        threat_trends = self._get_threat_trends()
        
        return {
            "dashboard_id": f"strategic_{now.timestamp()}",
            "generated_at": now.isoformat(),
            "threat_actor_summary": actor_summary,
            "campaign_summary": campaign_summary,
            "risk_summary": risk_summary,
            "emerging_threats": emerging_threats,
            "threat_trends": threat_trends,
            "key_metrics": self._calculate_key_metrics(actor_summary, campaign_summary, risk_summary),
        }

    def _get_actor_summary(self) -> Dict[str, Any]:
        """Get threat actor summary."""
        actors = list(self.store.threat_actors.values())
        
        by_type = {}
        by_sponsor = {}
        by_threat_level = {}
        
        for actor in actors:
            atype = actor.get("type", "UNKNOWN")
            sponsor = actor.get("sponsor", "UNKNOWN")
            level = actor.get("threat_level", "MEDIUM")
            
            by_type[atype] = by_type.get(atype, 0) + 1
            by_sponsor[sponsor] = by_sponsor.get(sponsor, 0) + 1
            by_threat_level[level] = by_threat_level.get(level, 0) + 1
        
        # Top threat actors
        top_actors = []
        for actor in sorted(actors, key=lambda x: x.get("metadata", {}).get("threat_score", 0), reverse=True)[:5]:
            top_actors.append({
                "actor_id": actor.get("actor_id"),
                "name": actor.get("name"),
                "type": actor.get("type"),
                "threat_level": actor.get("threat_level"),
                "active_campaigns": len([
                    c for c in self.store.campaigns.values()
                    if actor.get("actor_id") in c.get("threat_actor_ids", [])
                    and c.get("status") in ("ACTIVE", "EMERGING")
                ]),
            })
        
        return {
            "total_actors": len(actors),
            "by_type": by_type,
            "by_sponsor": by_sponsor,
            "by_threat_level": by_threat_level,
            "top_actors": top_actors,
        }

    def _get_campaign_summary(self) -> Dict[str, Any]:
        """Get campaign summary."""
        campaigns = list(self.store.campaigns.values())
        
        by_status = {}
        by_scale = {}
        by_target_sector = {}
        
        for campaign in campaigns:
            status = campaign.get("status", "UNKNOWN")
            scale = campaign.get("scale", "MEDIUM")
            
            by_status[status] = by_status.get(status, 0) + 1
            by_scale[scale] = by_scale.get(scale, 0) + 1
            
            for sector in campaign.get("target_sectors", []):
                by_target_sector[sector] = by_target_sector.get(sector, 0) + 1
        
        # Active campaigns with attribution
        active_campaigns = []
        for campaign in campaigns:
            if campaign.get("status") in ("ACTIVE", "EMERGING"):
                attribution = self.store.get_attribution_for_campaign(campaign.get("campaign_id"))
                active_campaigns.append({
                    "campaign_id": campaign.get("campaign_id"),
                    "name": campaign.get("name"),
                    "status": campaign.get("status"),
                    "scale": campaign.get("scale"),
                    "attributed_actor": attribution.get("primary_actor_id") if attribution else None,
                    "confidence": attribution.get("confidence", "UNATTRIBUTED") if attribution else "UNATTRIBUTED",
                })
        
        return {
            "total_campaigns": len(campaigns),
            "active_campaigns": len(active_campaigns),
            "by_status": by_status,
            "by_scale": by_scale,
            "by_target_sector": by_target_sector,
            "active_campaign_list": active_campaigns[:10],
        }

    def _get_risk_summary(self) -> Dict[str, Any]:
        """Get risk summary."""
        assessments = list(self.store.risk_assessments.values())
        
        by_level = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        for assessment in assessments:
            level = assessment.get("risk_level", "MEDIUM")
            by_level[level] = by_level.get(level, 0) + 1
        
        # Average risk score
        avg_score = 0
        if assessments:
            avg_score = sum(a.get("risk_score", 0) for a in assessments) / len(assessments)
        
        return {
            "total_assessments": len(assessments),
            "by_level": by_level,
            "average_risk_score": avg_score,
            "high_risk_entities": [
                {"entity_id": a.get("entity_id"), "score": a.get("risk_score")}
                for a in sorted(assessments, key=lambda x: x.get("risk_score", 0), reverse=True)[:5]
            ],
        }

    def _get_emerging_threats(self) -> List[Dict[str, Any]]:
        """Get emerging threats."""
        threats = []
        
        # Emerging campaigns
        for campaign in self.store.campaigns.values():
            if campaign.get("status") == "EMERGING":
                threats.append({
                    "threat_type": "EMERGING_CAMPAIGN",
                    "title": campaign.get("name", "Unnamed Campaign"),
                    "description": campaign.get("description", ""),
                    "severity": "HIGH",
                    "entities": campaign.get("target_sectors", []),
                    "timestamp": campaign.get("discovered_date"),
                })
        
        # New threat actors
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        for actor in self.store.threat_actors.values():
            discovered = actor.get("metadata", {}).get("discovered_date")
            if discovered:
                if isinstance(discovered, str):
                    discovered = datetime.fromisoformat(discovered.replace("Z", "+00:00"))
                if discovered >= cutoff:
                    threats.append({
                        "threat_type": "NEW_ACTOR",
                        "title": f"New {actor.get('type', 'Unknown')} Actor: {actor.get('name', 'Unknown')}",
                        "description": actor.get("description", ""),
                        "severity": actor.get("threat_level", "MEDIUM"),
                        "entities": actor.get("primary_targets", []),
                        "timestamp": discovered.isoformat(),
                    })
        
        return sorted(threats, key=lambda x: x.get("severity", "LOW"), reverse=True)[:10]

    def _get_threat_trends(self) -> Dict[str, Any]:
        """Get threat trends over time."""
        # Analyze campaign discovery over time
        campaigns_by_month = {}
        for campaign in self.store.campaigns.values():
            discovered = campaign.get("discovered_date")
            if discovered:
                if isinstance(discovered, str):
                    discovered = datetime.fromisoformat(discovered.replace("Z", "+00:00"))
                month_key = discovered.strftime("%Y-%m")
                campaigns_by_month[month_key] = campaigns_by_month.get(month_key, 0) + 1
        
        # Analyze actor activity
        actors_by_month = {}
        for actor in self.store.threat_actors.values():
            last_activity = actor.get("last_activity")
            if last_activity:
                if isinstance(last_activity, str):
                    last_activity = datetime.fromisoformat(last_activity.replace("Z", "+00:00"))
                month_key = last_activity.strftime("%Y-%m")
                actors_by_month[month_key] = actors_by_month.get(month_key, 0) + 1
        
        return {
            "campaigns_by_month": campaigns_by_month,
            "actor_activity_by_month": actors_by_month,
            "trend_direction": "INCREASING" if campaigns_by_month else "STABLE",
        }

    def _calculate_key_metrics(
        self,
        actor_summary: Dict,
        campaign_summary: Dict,
        risk_summary: Dict,
    ) -> Dict[str, Any]:
        """Calculate key dashboard metrics."""
        return {
            "total_active_threats": actor_summary["by_threat_level"].get("CRITICAL", 0) + 
                                    actor_summary["by_threat_level"].get("HIGH", 0),
            "active_campaigns": campaign_summary["active_campaigns"],
            "average_risk_score": risk_summary["average_risk_score"],
            "critical_risk_entities": risk_summary["by_level"].get("CRITICAL", 0),
            "nation_state_actors": actor_summary["by_type"].get("NATION_STATE", 0),
            "attribution_rate": self._calculate_attribution_rate(),
        }

    def _calculate_attribution_rate(self) -> float:
        """Calculate campaign attribution rate."""
        campaigns = list(self.store.campaigns.values())
        if not campaigns:
            return 0.0
        
        attributed = 0
        for campaign in campaigns:
            if self.store.get_attribution_for_campaign(campaign.get("campaign_id")):
                attributed += 1
        
        return (attributed / len(campaigns)) * 100

    def generate_executive_brief(self) -> Dict[str, Any]:
        """Generate executive threat briefing.
        
        Returns:
            Executive briefing data
        """
        dashboard = self.generate_dashboard()
        
        # Key findings
        findings = []
        
        critical_actors = dashboard["threat_actor_summary"]["by_threat_level"].get("CRITICAL", 0)
        if critical_actors > 0:
            findings.append({
                "priority": "CRITICAL",
                "finding": f"{critical_actors} critical-level threat actors identified",
            })
        
        active_campaigns = dashboard["campaign_summary"]["active_campaigns"]
        if active_campaigns > 5:
            findings.append({
                "priority": "HIGH",
                "finding": f"{active_campaigns} active campaigns currently in progress",
            })
        
        high_risk = dashboard["risk_summary"]["by_level"].get("HIGH", 0)
        if high_risk > 0:
            findings.append({
                "priority": "HIGH",
                "finding": f"{high_risk} entities assessed at high risk",
            })
        
        # Recommended actions
        actions = [
            "Review and update threat actor profiles",
            "Enhance monitoring for active campaigns",
            "Update defensive controls based on current TTPs",
        ]
        
        return {
            "brief_id": f"brief_{datetime.now(timezone.utc).timestamp()}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": "Current Quarter",
            "key_findings": findings,
            "recommended_actions": actions,
            "dashboard_summary": dashboard,
        }


def get_strategic_dashboard() -> StrategicThreatDashboard:
    """Get the global strategic dashboard instance."""
    from .store import get_warfare_store
    from .threat_actor_engine import get_threat_actor_engine
    from .attribution_engine import get_attribution_engine
    
    store = get_warfare_store()
    actor_engine = get_threat_actor_engine()
    attribution_engine = get_attribution_engine()
    
    return StrategicThreatDashboard(store, actor_engine, attribution_engine)