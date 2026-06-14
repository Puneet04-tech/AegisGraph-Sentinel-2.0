"""
Insider Threat Storage Engine.

Thread-safe storage for insider threat intelligence.
"""

from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    InsiderProfile,
    BehavioralBaseline,
    ActivityRecord,
    ThreatIndicator,
    InsiderCampaign,
)

logger = logging.getLogger(__name__)


class InsiderThreatStore:
    """Thread-safe storage for insider threat data."""
    
    def __init__(self):
        self._lock = Lock()
        self._profiles: Dict[str, InsiderProfile] = {}
        self._baselines: Dict[str, BehavioralBaseline] = {}
        self._activities: Dict[str, ActivityRecord] = {}
        self._indicators: Dict[str, ThreatIndicator] = {}
        self._campaigns: Dict[str, InsiderCampaign] = {}
        logger.info("Insider threat store initialized")
    
    def store_profile(self, profile: InsiderProfile) -> InsiderProfile:
        with self._lock:
            self._profiles[profile.profile_id] = profile
        return profile
    
    def get_profile(self, profile_id: str) -> Optional[InsiderProfile]:
        return self._profiles.get(profile_id)
    
    def get_employee_profile(self, employee_id: str) -> Optional[InsiderProfile]:
        for p in self._profiles.values():
            if p.employee_id == employee_id:
                return p
        return None
    
    def store_baseline(self, baseline: BehavioralBaseline) -> BehavioralBaseline:
        with self._lock:
            self._baselines[baseline.baseline_id] = baseline
        return baseline
    
    def get_employee_baselines(self, employee_id: str) -> List[BehavioralBaseline]:
        return [b for b in self._baselines.values() if b.employee_id == employee_id]
    
    def store_activity(self, activity: ActivityRecord) -> ActivityRecord:
        with self._lock:
            self._activities[activity.activity_id] = activity
        return activity
    
    def get_employee_activities(self, employee_id: str, limit: int = 100) -> List[ActivityRecord]:
        activities = [a for a in self._activities.values() if a.employee_id == employee_id]
        return sorted(activities, key=lambda x: x.timestamp, reverse=True)[:limit]
    
    def store_indicator(self, indicator: ThreatIndicator) -> ThreatIndicator:
        with self._lock:
            self._indicators[indicator.indicator_id] = indicator
        return indicator
    
    def get_employee_indicators(self, employee_id: str) -> List[ThreatIndicator]:
        return [i for i in self._indicators.values() if i.employee_id == employee_id]
    
    def get_active_indicators(self) -> List[ThreatIndicator]:
        return [i for i in self._indicators.values() if not i.resolved]
    
    def store_campaign(self, campaign: InsiderCampaign) -> InsiderCampaign:
        with self._lock:
            self._campaigns[campaign.campaign_id] = campaign
        return campaign
    
    def get_campaign(self, campaign_id: str) -> Optional[InsiderCampaign]:
        return self._campaigns.get(campaign_id)
    
    def get_active_campaigns(self) -> List[InsiderCampaign]:
        return [c for c in self._campaigns.values() if c.status == "ACTIVE"]
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "profiles": len(self._profiles),
            "baselines": len(self._baselines),
            "activities": len(self._activities),
            "active_indicators": len(self.get_active_indicators()),
            "active_campaigns": len(self.get_active_campaigns()),
        }


_insider_store: Optional[InsiderThreatStore] = None


def get_insider_store() -> InsiderThreatStore:
    global _insider_store
    if _insider_store is None:
        _insider_store = InsiderThreatStore()
    return _insider_store