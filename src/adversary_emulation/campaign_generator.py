import uuid
from .models import AdversaryProfile, AttackCampaign, SimulationStep

class CampaignGenerator:
    """Generates attack campaigns from adversary profiles.

    Responsible for mapping an AdversaryProfile to an AttackCampaign by
    translating each tactic into a SimulationStep. Used by the red-team
    emulation pipeline to construct repeatable campaign runbooks.
    """

    def generate(self, profile: AdversaryProfile, target: str) -> AttackCampaign:
        steps = [
            SimulationStep(step_id=str(uuid.uuid4()), tactic=t, technique="Simulated", status="PENDING")
            for t in profile.tactics
        ]
        return AttackCampaign(id=str(uuid.uuid4()), profile_id=profile.id, target_entity=target, steps=steps)
