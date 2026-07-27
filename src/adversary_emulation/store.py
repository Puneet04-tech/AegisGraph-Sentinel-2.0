from typing import Dict, Optional
from threading import Lock
from .models import AdversaryProfile, AttackCampaign, SimulationResult

class AdversaryStore:
    def __init__(self):
        self._lock = Lock()
        self.profiles: Dict[str, AdversaryProfile] = {}
        self.campaigns: Dict[str, AttackCampaign] = {}
        self.results: Dict[str, SimulationResult] = {}

    def save_profile(self, profile: AdversaryProfile) -> None:
        """Save an adversary profile to the store."""
        with self._lock:
            self.profiles[profile.id] = profile

    def get_profile(self, profile_id: str) -> Optional[AdversaryProfile]:
        """Retrieve an adversary profile by ID, or None if not found."""
        with self._lock:
            return self.profiles.get(profile_id)

    def save_campaign(self, campaign: AttackCampaign) -> None:
        """Save an attack campaign to the store."""
        with self._lock:
            self.campaigns[campaign.id] = campaign

    def save_result(self, result: SimulationResult) -> None:
        """Save a simulation result to the store."""
        with self._lock:
            self.results[result.campaign_id] = result
