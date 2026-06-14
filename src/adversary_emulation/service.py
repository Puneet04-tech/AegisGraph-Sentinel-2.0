from .models import AdversaryProfile, AttackCampaign, SimulationResult
from .store import AdversaryStore
from .campaign_generator import CampaignGenerator
from .simulation_engine import SimulationEngine

class AdversaryEmulationService:
    def __init__(self):
        self.store = AdversaryStore()
        self.generator = CampaignGenerator()
        self.engine = SimulationEngine()

    def create_profile(self, profile: AdversaryProfile):
        self.store.save_profile(profile)
        return profile

    def get_profile(self, profile_id: str) -> AdversaryProfile:
        return self.store.get_profile(profile_id)

    def generate_campaign(self, profile_id: str, target: str) -> AttackCampaign:
        profile = self.store.get_profile(profile_id)
        if not profile:
            raise ValueError("Profile not found")
        campaign = self.generator.generate(profile, target)
        self.store.save_campaign(campaign)
        return campaign

    def run_simulation(self, campaign_id: str) -> SimulationResult:
        campaign = self.store.campaigns.get(campaign_id)
        if not campaign:
            raise ValueError("Campaign not found")
        result = self.engine.execute(campaign)
        self.store.save_result(result)
        return result
