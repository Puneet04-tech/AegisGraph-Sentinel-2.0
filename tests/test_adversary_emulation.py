from src.adversary_emulation.models import AdversaryProfile
from src.adversary_emulation.service import AdversaryEmulationService

def test_adversary_emulation():
    service = AdversaryEmulationService()
    profile = AdversaryProfile(id="APT29", name="Cozy Bear", tactics=["Reconnaissance"], techniques=["Phishing"])
    service.create_profile(profile)
    fetched = service.get_profile("APT29")
    assert fetched.name == "Cozy Bear"

    campaign = service.generate_campaign("APT29", "target_corp")
    assert len(campaign.steps) == 1

    result = service.run_simulation(campaign.id)
    assert result.total_steps == 1
