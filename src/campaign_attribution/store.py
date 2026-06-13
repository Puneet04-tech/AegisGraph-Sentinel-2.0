"""
Campaign Attribution Store - Thread-safe storage with LRU cache
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional

from .models import (
    ThreatActor,
    Campaign,
    Attribution,
    ThreatProfile,
    AttackPattern,
    RiskAssessment,
    Infrastructure,
    CampaignStats,
    ActorType,
    CampaignStatus,
)


class LRUCache:
    """Thread-safe LRU cache with bounded size."""

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.cache: OrderedDict = OrderedDict()
        self.lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                return self.cache[key]
            return None

    def put(self, key: str, value: Any) -> None:
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

    def delete(self, key: str) -> None:
        with self.lock:
            if key in self.cache:
                del self.cache[key]

    def clear(self) -> None:
        with self.lock:
            self.cache.clear()

    def size(self) -> int:
        with self.lock:
            return len(self.cache)


class CampaignStore:
    """
    Thread-safe storage for campaign attribution data.
    Uses LRU cache for O(1) lookup of frequently accessed records.
    """

    def __init__(self, max_cache_size: int = 10000):
        self._campaigns: Dict[str, Campaign] = {}
        self._actors: Dict[str, ThreatActor] = {}
        self._attributions: Dict[str, Attribution] = {}
        self._profiles: Dict[str, ThreatProfile] = {}
        self._patterns: Dict[str, AttackPattern] = {}
        self._assessments: Dict[str, RiskAssessment] = {}
        self._infrastructure: Dict[str, Infrastructure] = {}
        self._campaign_index: Dict[str, List[str]] = {}
        self._actor_index: Dict[str, List[str]] = {}
        self._lock = threading.RLock()
        self._cache = LRUCache(max_cache_size)
        self._stats = CampaignStats()

    def store_campaign(self, campaign: Campaign) -> bool:
        """Store a campaign."""
        with self._lock:
            self._campaigns[campaign.campaign_id] = campaign
            self._cache.put(f"campaign:{campaign.campaign_id}", campaign)

            status = campaign.status.value
            if status not in self._campaign_index:
                self._campaign_index[status] = []
            if campaign.campaign_id not in self._campaign_index[status]:
                self._campaign_index[status].append(campaign.campaign_id)

            self._update_stats()
            return True

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """Get a campaign by ID."""
        cached = self._cache.get(f"campaign:{campaign_id}")
        if cached:
            return cached

        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign:
                self._cache.put(f"campaign:{campaign_id}", campaign)
            return campaign

    def store_actor(self, actor: ThreatActor) -> bool:
        """Store a threat actor."""
        with self._lock:
            self._actors[actor.actor_id] = actor
            self._cache.put(f"actor:{actor.actor_id}", actor)

            actor_type = actor.actor_type.value
            if actor_type not in self._actor_index:
                self._actor_index[actor_type] = []
            if actor.actor_id not in self._actor_index[actor_type]:
                self._actor_index[actor_type].append(actor.actor_id)

            self._update_stats()
            return True

    def get_actor(self, actor_id: str) -> Optional[ThreatActor]:
        """Get a threat actor by ID."""
        cached = self._cache.get(f"actor:{actor_id}")
        if cached:
            return cached

        with self._lock:
            actor = self._actors.get(actor_id)
            if actor:
                self._cache.put(f"actor:{actor_id}", actor)
            return actor

    def store_attribution(self, attribution: Attribution) -> bool:
        """Store an attribution."""
        with self._lock:
            self._attributions[attribution.attribution_id] = attribution
            self._cache.put(f"attribution:{attribution.attribution_id}", attribution)
            return True

    def get_attribution(self, attribution_id: str) -> Optional[Attribution]:
        """Get an attribution by ID."""
        cached = self._cache.get(f"attribution:{attribution_id}")
        if cached:
            return cached

        with self._lock:
            return self._attributions.get(attribution_id)

    def store_profile(self, profile: ThreatProfile) -> bool:
        """Store a threat profile."""
        with self._lock:
            self._profiles[profile.profile_id] = profile
            self._cache.put(f"profile:{profile.profile_id}", profile)
            return True

    def get_profile(self, profile_id: str) -> Optional[ThreatProfile]:
        """Get a threat profile by ID."""
        cached = self._cache.get(f"profile:{profile_id}")
        if cached:
            return cached

        with self._lock:
            return self._profiles.get(profile_id)

    def store_infrastructure(self, infra: Infrastructure) -> bool:
        """Store infrastructure."""
        with self._lock:
            self._infrastructure[infra.infrastructure_id] = infra
            self._cache.put(f"infra:{infra.infrastructure_id}", infra)
            self._update_stats()
            return True

    def get_infrastructure(self, infra_id: str) -> Optional[Infrastructure]:
        """Get infrastructure by ID."""
        cached = self._cache.get(f"infra:{infra_id}")
        if cached:
            return cached

        with self._lock:
            return self._infrastructure.get(infra_id)

    def store_pattern(self, pattern: AttackPattern) -> bool:
        """Store an attack pattern."""
        with self._lock:
            self._patterns[pattern.pattern_id] = pattern
            return True

    def get_pattern(self, pattern_id: str) -> Optional[AttackPattern]:
        """Get an attack pattern by ID."""
        with self._lock:
            return self._patterns.get(pattern_id)

    def get_campaigns_by_status(self, status: CampaignStatus) -> List[Campaign]:
        """Get campaigns by status."""
        with self._lock:
            campaign_ids = self._campaign_index.get(status.value, [])
            return [self._campaigns[cid] for cid in campaign_ids if cid in self._campaigns]

    def get_campaigns_by_actor(self, actor_id: str) -> List[Campaign]:
        """Get campaigns linked to an actor."""
        with self._lock:
            return [
                c for c in self._campaigns.values()
                if actor_id in c.attributed_actors
            ]

    def get_actors_by_type(self, actor_type: ActorType) -> List[ThreatActor]:
        """Get actors by type."""
        with self._lock:
            actor_ids = self._actor_index.get(actor_type.value, [])
            return [self._actors[aid] for aid in actor_ids if aid in self._actors]

    def get_campaigns_by_sector(self, sector: str) -> List[Campaign]:
        """Get campaigns targeting a sector."""
        with self._lock:
            return [c for c in self._campaigns.values() if sector in c.target_sectors]

    def get_active_campaigns(self) -> List[Campaign]:
        """Get all active campaigns."""
        return self.get_campaigns_by_status(CampaignStatus.ACTIVE)

    def get_attributed_campaigns(self) -> List[Campaign]:
        """Get all attributed campaigns."""
        with self._lock:
            return [c for c in self._campaigns.values() if c.attributed_actors]

    def get_active_actors(self) -> List[ThreatActor]:
        """Get all active actors."""
        with self._lock:
            return [a for a in self._actors.values() if a.is_active]

    def link_campaign_to_actor(self, campaign_id: str, actor_id: str) -> bool:
        """Link a campaign to an actor."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            actor = self._actors.get(actor_id)
            if not campaign or not actor:
                return False

            if actor_id not in campaign.attributed_actors:
                campaign.attributed_actors.append(actor_id)
                self._campaigns[campaign_id] = campaign

            if campaign_id not in actor.linked_campaigns:
                actor.linked_campaigns.append(campaign_id)
                self._actors[actor_id] = actor

            return True

    def link_infrastructure_to_campaign(self, infra_id: str, campaign_id: str) -> bool:
        """Link infrastructure to a campaign."""
        with self._lock:
            infra = self._infrastructure.get(infra_id)
            campaign = self._campaigns.get(campaign_id)
            if not infra or not campaign:
                return False

            if campaign_id not in infra.linked_campaigns:
                infra.linked_campaigns.append(campaign_id)
                self._infrastructure[infra_id] = infra

            if infra_id not in campaign.linked_infrastructure:
                campaign.linked_infrastructure.append(infra_id)
                self._campaigns[campaign_id] = campaign

            return True

    def _update_stats(self) -> None:
        """Update campaign statistics."""
        self._stats.total_campaigns = len(self._campaigns)
        self._stats.active_campaigns = len(self.get_active_campaigns())
        self._stats.attributed_campaigns = len(self.get_attributed_campaigns())
        self._stats.total_actors = len(self._actors)
        self._stats.active_actors = len(self.get_active_actors())
        self._stats.total_infrastructure = len(self._infrastructure)

        self._stats.campaigns_by_status = {
            status: len(ids) for status, ids in self._campaign_index.items()
        }

    def get_stats(self) -> CampaignStats:
        """Get current statistics."""
        with self._lock:
            self._update_stats()
            return self._stats

    def clear(self) -> None:
        """Clear all stored data."""
        with self._lock:
            self._campaigns.clear()
            self._actors.clear()
            self._attributions.clear()
            self._profiles.clear()
            self._patterns.clear()
            self._assessments.clear()
            self._infrastructure.clear()
            self._campaign_index.clear()
            self._actor_index.clear()
            self._cache.clear()
            self._stats = CampaignStats()


# Singleton instance
_campaign_store: Optional[CampaignStore] = None
_store_lock = threading.Lock()


def get_campaign_store() -> CampaignStore:
    """Get the singleton CampaignStore instance."""
    global _campaign_store
    with _store_lock:
        if _campaign_store is None:
            _campaign_store = CampaignStore()
        return _campaign_store


def reset_campaign_store() -> None:
    """Reset the singleton store (for testing)."""
    global _campaign_store
    with _store_lock:
        if _campaign_store:
            _campaign_store.clear()
        _campaign_store = None
