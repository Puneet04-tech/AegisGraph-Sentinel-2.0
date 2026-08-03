"""Adversary Emulation Service Module

High-level service for managing adversary profiles, campaign generation,
and simulation execution.
"""
from .models import AdversaryProfile, AttackCampaign, SimulationResult
from .store import AdversaryStore
from .campaign_generator import CampaignGenerator
from .simulation_engine import SimulationEngine


class AdversaryEmulationService:
    """High-level service for adversary emulation workflows.

    The AdversaryEmulationService orchestrates the full red-team adversary
    emulation lifecycle. It provides three main operations:

    1. **Profile Management**: Create and retrieve adversary profiles that
       define threat actors, their tactics, techniques, and procedures (TTPs).
    2. **Campaign Generation**: Generate targeted attack campaigns from a
       given adversary profile and a specific target entity.
    3. **Simulation Execution**: Execute a campaign through the simulation
       engine and record structured results.

    Internally, the service coordinates three sub-components:
    - :class:`AdversaryStore` for persisting profiles, campaigns, and results
    - :class:`CampaignGenerator` for building attack sequences from profiles
    - :class:`SimulationEngine` for running step-by-step campaign execution

    Usage:
        service = AdversaryEmulationService()
        profile = service.create_profile(adversary_profile)
        campaign = service.generate_campaign(profile.id, target="acme-corp")
        result = service.run_simulation(campaign.id)
    """

    def __init__(self) -> None:
        """Initialize the service with a store, campaign generator, and engine."""
        self.store = AdversaryStore()
        self.generator = CampaignGenerator()
        self.engine = SimulationEngine()

    def create_profile(self, profile: AdversaryProfile) -> AdversaryProfile:
        """Create and persist a new adversary profile.

        Args:
            profile: The adversary profile to store.

        Returns:
            The stored AdversaryProfile.
        """
        self.store.save_profile(profile)
        return profile

    def get_profile(self, profile_id: str) -> AdversaryProfile:
        """Retrieve an adversary profile by ID.

        Args:
            profile_id: The unique identifier of the profile.

        Returns:
            The AdversaryProfile if found, None otherwise.
        """
        return self.store.get_profile(profile_id)

    def generate_campaign(
        self, profile_id: str, target: str
    ) -> AttackCampaign:
        """Generate an attack campaign for a given profile and target.

        Args:
            profile_id: The ID of the adversary profile to use.
            target: The target entity for the campaign.

        Returns:
            The generated AttackCampaign.

        Raises:
            ValueError: If no profile exists for the given profile_id.
        """
        profile = self.store.get_profile(profile_id)
        if not profile:
            raise ValueError("Profile not found")
        campaign = self.generator.generate(profile, target)
        self.store.save_campaign(campaign)
        return campaign

    def run_simulation(self, campaign_id: str) -> SimulationResult:
        """Execute a simulation for a given campaign.

        Args:
            campaign_id: The ID of the campaign to simulate.

        Returns:
            The SimulationResult from the engine.

        Raises:
            ValueError: If no campaign exists for the given campaign_id.
        """
        campaign = self.store.campaigns.get(campaign_id)
        if not campaign:
            raise ValueError("Campaign not found")
        result = self.engine.execute(campaign)
        self.store.save_result(result)
        return result
