"""
Thread-safe storage layer for AI Threat Hunting & Security Analytics Platform
"""

import time
import threading
from collections import OrderedDict
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from .models import (
    ThreatHunt,
    ThreatIndicator,
    BehaviorProfile,
    ThreatCampaign,
    AttackPath,
    ThreatCorrelation,
    ThreatScore,
    HuntResult,
)


class LRUCache(OrderedDict):
    """Simple thread-safe LRU Cache."""

    def __init__(self, maxsize: int = 1000):
        super().__init__()
        self.maxsize = maxsize
        self.lock = threading.Lock()

    def __getitem__(self, key):
        with self.lock:
            value = super().__getitem__(key)
            self.move_to_end(key)
            return value

    def __setitem__(self, key, value):
        with self.lock:
            if key in self:
                self.move_to_end(key)
            super().__setitem__(key, value)
            if len(self) > self.maxsize:
                oldest = next(iter(self))
                del self[oldest]

    def get(self, key, default=None):
        with self.lock:
            try:
                self.move_to_end(key)
                return super().__getitem__(key)
            except KeyError:
                return default


class ThreatHuntingStore:
    """In-memory datastore for AI threat hunting."""

    def __init__(self, cache_size: int = 1000, default_ttl: float = 300.0):
        self.cache_size = cache_size
        self.default_ttl = default_ttl
        self.lock = threading.RLock()

        self.hunts: Dict[str, ThreatHunt] = {}
        self.results: Dict[str, List[HuntResult]] = {}  # hunt_id -> List[HuntResult]
        self.profiles: Dict[str, BehaviorProfile] = {}
        self.campaigns: Dict[str, ThreatCampaign] = {}
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.correlations: Dict[str, ThreatCorrelation] = {}
        self.scores: LRUCache = LRUCache(maxsize=cache_size)
        self.history: List[Dict[str, Any]] = []
        self.max_history = 10000

        self.stats = {
            "hunts_started": 0,
            "results_recorded": 0,
            "profiles_updated": 0,
            "campaigns_detected": 0,
            "indicators_registered": 0,
            "correlations_made": 0,
        }

    # Hunts
    def add_hunt(self, hunt: ThreatHunt) -> ThreatHunt:
        with self.lock:
            self.hunts[hunt.hunt_id] = hunt
            self.stats["hunts_started"] += 1
            return hunt

    def get_hunt(self, hunt_id: str) -> Optional[ThreatHunt]:
        with self.lock:
            return self.hunts.get(hunt_id)

    def list_hunts(self) -> List[ThreatHunt]:
        with self.lock:
            return list(self.hunts.values())

    def update_hunt_state(self, hunt_id: str, **kwargs) -> Optional[ThreatHunt]:
        with self.lock:
            hunt = self.hunts.get(hunt_id)
            if hunt:
                for key, val in kwargs.items():
                    if hasattr(hunt, key):
                        setattr(hunt, key, val)
                return hunt
        return None

    # Results
    def add_result(self, result: HuntResult) -> HuntResult:
        with self.lock:
            if result.hunt_id not in self.results:
                self.results[result.hunt_id] = []
            self.results[result.hunt_id].append(result)
            self.stats["results_recorded"] += 1
            return result

    def get_results_for_hunt(self, hunt_id: str) -> List[HuntResult]:
        with self.lock:
            return self.results.get(hunt_id, [])

    # Profiles
    def set_profile(self, profile: BehaviorProfile) -> BehaviorProfile:
        with self.lock:
            profile.last_updated = datetime.now(timezone.utc).isoformat()
            self.profiles[profile.entity_id] = profile
            self.stats["profiles_updated"] += 1
            return profile

    def get_profile(self, entity_id: str) -> Optional[BehaviorProfile]:
        with self.lock:
            return self.profiles.get(entity_id)

    # Campaigns
    def set_campaign(self, campaign: ThreatCampaign) -> ThreatCampaign:
        with self.lock:
            self.campaigns[campaign.campaign_id] = campaign
            self.stats["campaigns_detected"] += 1
            return campaign

    def get_campaign(self, campaign_id: str) -> Optional[ThreatCampaign]:
        with self.lock:
            return self.campaigns.get(campaign_id)

    def list_campaigns(self) -> List[ThreatCampaign]:
        with self.lock:
            return list(self.campaigns.values())

    # Indicators
    def register_indicator(self, indicator: ThreatIndicator) -> ThreatIndicator:
        with self.lock:
            self.indicators[indicator.indicator_id] = indicator
            self.stats["indicators_registered"] += 1
            return indicator

    def get_indicator(self, indicator_id: str) -> Optional[ThreatIndicator]:
        with self.lock:
            return self.indicators.get(indicator_id)

    def list_indicators(self) -> List[ThreatIndicator]:
        with self.lock:
            return list(self.indicators.values())

    # Correlations
    def add_correlation(self, correlation: ThreatCorrelation) -> ThreatCorrelation:
        with self.lock:
            self.correlations[correlation.correlation_id] = correlation
            self.stats["correlations_made"] += 1
            return correlation

    def list_correlations(self) -> List[ThreatCorrelation]:
        with self.lock:
            return list(self.correlations.values())

    # Scoring
    def get_threat_score(self, entity_id: str) -> Optional[ThreatScore]:
        return self.scores.get(entity_id)

    def set_threat_score(self, entity_id: str, score: ThreatScore):
        self.scores[entity_id] = score

    # History
    def record_history(self, action: str, details: Dict[str, Any]):
        with self.lock:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "details": details,
            }
            self.history.append(entry)
            if len(self.history) > self.max_history:
                self.history = self.history[-self.max_history:]

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "hunts_count": len(self.hunts),
                "profiles_count": len(self.profiles),
                "campaigns_count": len(self.campaigns),
                "indicators_count": len(self.indicators),
                "correlations_count": len(self.correlations),
                "scores_cached": len(self.scores),
                "stats_counters": self.stats.copy(),
            }

    def reset(self):
        with self.lock:
            self.hunts.clear()
            self.results.clear()
            self.profiles.clear()
            self.campaigns.clear()
            self.indicators.clear()
            self.correlations.clear()
            self.history.clear()
            for k in self.stats:
                self.stats[k] = 0


_store: Optional[ThreatHuntingStore] = None
_store_lock = threading.Lock()


def get_store() -> ThreatHuntingStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = ThreatHuntingStore()
    return _store
