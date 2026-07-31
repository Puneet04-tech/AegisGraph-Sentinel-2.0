"""Adversary Store Module

Thread-safe in-memory storage for adversary profiles, campaigns, and results.
"""
from typing import Dict, Optional
from threading import Lock
from .models import AdversaryProfile, AttackCampaign, SimulationResult


class AdversaryStore:
    """Thread-safe in-memory store for adversary emulation data.

    Provides lock-protected access to adversary profiles, attack campaigns,
    and simulation results. All public methods are safe for concurrent use.
    """

    def __init__(self) -> None:
        """Initialize an empty store with thread-safe locks."""
        self._lock = Lock()
        self.profiles: Dict[str, AdversaryProfile] = {}
        self.campaigns: Dict[str, AttackCampaign] = {}
        self.results: Dict[str, SimulationResult] = {}

    def save_profile(self, profile: AdversaryProfile) -> None:
        """Persist an adversary profile.

        Args:
            profile: The AdversaryProfile to store, keyed by its id.
        """
        with self._lock:
            self.profiles[profile.id] = profile

    def get_profile(self, profile_id: str) -> AdversaryProfile:
        """Retrieve an adversary profile by ID.

        Args:
            profile_id: The unique identifier of the profile.

        Returns:
            The AdversaryProfile if found, None otherwise.
        """
        with self._lock:
            return self.profiles.get(profile_id)

    def save_campaign(self, campaign: AttackCampaign) -> None:
        """Persist an attack campaign.

        Args:
            campaign: The AttackCampaign to store, keyed by its id.
        """
        with self._lock:
            self.campaigns[campaign.id] = campaign

    def save_result(self, result: SimulationResult) -> None:
        """Persist a simulation result.

        Args:
            result: The SimulationResult to store, keyed by campaign_id.
        """
        with self._lock:
            self.results[result.campaign_id] = result
