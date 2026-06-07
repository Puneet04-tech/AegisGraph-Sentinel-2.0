"""Thread-safe in-memory store for Threat Intelligence entities.

Manages caching, storage, and retrieval of indicators, actors, and campaigns.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Dict, List, Optional, Set

from .models import (
    ThreatIndicator,
    ThreatActor,
    FraudCampaign,
    AttackPattern,
    ThreatCorrelation,
)


class _LRUDict(OrderedDict):
    """Bounded LRU dictionary — same pattern as CaseStore."""

    def __init__(self, maxsize: int = 10_000):
        self.maxsize = maxsize
        super().__init__()

    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        if len(self) > self.maxsize:
            self.popitem(last=False)

    def __getitem__(self, key):
        value = super().__getitem__(key)
        self.move_to_end(key)
        return value


class ThreatStore:
    """Singleton in-memory store for Threat Intelligence."""

    def __init__(self):
        self._lock = threading.RLock()
        self._indicators: _LRUDict = _LRUDict(maxsize=50_000)
        self._actors: _LRUDict = _LRUDict(maxsize=10_000)
        self._campaigns: _LRUDict = _LRUDict(maxsize=5_000)
        self._correlations: _LRUDict = _LRUDict(maxsize=20_000)
        self._patterns: Dict[str, AttackPattern] = {}

        # Default attack patterns
        self._init_default_patterns()

    def _init_default_patterns(self):
        patterns = [
            AttackPattern(name="Credential Stuffing", description="Rapid failures followed by success", tactics=["TA0006", "TA0011"]),
            AttackPattern(name="Mule Laundering Ring", description="Funds layering through multiple intermediate hops", tactics=["TA0008", "Mule Chain"]),
            AttackPattern(name="Behavioral stress bypass", description="High biometric stress and rapid keystroke variations", tactics=["TA0001", "Stress Alert"]),
        ]
        for p in patterns:
            self._patterns[p.pattern_id] = p

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------
    def add_indicator(
        self,
        indicator_type: str,
        value: str,
        source_feed: str,
        threat_score: float,
        confidence: float,
    ) -> ThreatIndicator:
        with self._lock:
            # Check if exists, update last_seen/confidence/score
            key = f"{indicator_type}:{value}"
            existing = self._indicators.get(key)
            if existing:
                existing.threat_score = max(existing.threat_score, threat_score)
                existing.confidence = max(existing.confidence, confidence)
                from .models import _utcnow
                existing.last_seen = _utcnow()
                return existing
            
            ind = ThreatIndicator(
                indicator_type=indicator_type,
                value=value,
                source_feed=source_feed,
                threat_score=threat_score,
                confidence=confidence,
            )
            self._indicators[key] = ind
            return ind

    def get_indicator(self, indicator_type: str, value: str) -> Optional[ThreatIndicator]:
        with self._lock:
            return self._indicators.get(f"{indicator_type}:{value}")

    def list_indicators(self, indicator_type: Optional[str] = None) -> List[ThreatIndicator]:
        with self._lock:
            items = list(self._indicators.values())
            if indicator_type:
                return [i for i in items if i.indicator_type == indicator_type]
            return items

    # ------------------------------------------------------------------
    # Threat Actors
    # ------------------------------------------------------------------
    def create_actor(self, name: str, risk_score: float) -> ThreatActor:
        with self._lock:
            actor = ThreatActor(name=name, risk_score=risk_score)
            self._actors[actor.actor_id] = actor
            return actor

    def get_actor(self, actor_id: str) -> Optional[ThreatActor]:
        with self._lock:
            return self._actors.get(actor_id)

    def list_actors(self) -> List[ThreatActor]:
        with self._lock:
            return list(self._actors.values())

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------
    def create_campaign(
        self,
        name: str,
        description: str,
        attack_pattern: str,
        severity: str,
        threat_actor_id: Optional[str] = None,
    ) -> FraudCampaign:
        with self._lock:
            campaign = FraudCampaign(
                name=name,
                description=description,
                attack_pattern=attack_pattern,
                severity=severity,
                status="ACTIVE",
                threat_actor_id=threat_actor_id,
            )
            self._campaigns[campaign.campaign_id] = campaign
            if threat_actor_id:
                actor = self.get_actor(threat_actor_id)
                if actor and campaign.campaign_id not in actor.campaign_ids:
                    actor.campaign_ids.append(campaign.campaign_id)
            return campaign

    def get_campaign(self, campaign_id: str) -> Optional[FraudCampaign]:
        with self._lock:
            return self._campaigns.get(campaign_id)

    def list_campaigns(self, status: Optional[str] = None) -> List[FraudCampaign]:
        with self._lock:
            campaigns = list(self._campaigns.values())
            if status:
                return [c for c in campaigns if c.status == status]
            return campaigns

    # ------------------------------------------------------------------
    # Correlations
    # ------------------------------------------------------------------
    def add_correlation(self, correlation: ThreatCorrelation) -> None:
        with self._lock:
            self._correlations[correlation.correlation_id] = correlation

    def list_correlations(self) -> List[ThreatCorrelation]:
        with self._lock:
            return list(self._correlations.values())


# Singleton management
_threat_store_instance: Optional[ThreatStore] = None
_threat_store_lock = threading.Lock()


def get_threat_store() -> ThreatStore:
    global _threat_store_instance
    if _threat_store_instance is None:
        with _threat_store_lock:
            if _threat_store_instance is None:
                _threat_store_instance = ThreatStore()
    return _threat_store_instance
