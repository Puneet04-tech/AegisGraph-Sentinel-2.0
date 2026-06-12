import uuid
from .models import AdversaryProfile, AttackCampaign, SimulationStep

class CampaignGenerator:
    def generate(self, profile: AdversaryProfile, target: str) -> AttackCampaign:
        steps = [
            SimulationStep(step_id=str(uuid.uuid4()), tactic=t, technique="Simulated", status="PENDING")
            for t in profile.tactics
        ]
        return AttackCampaign(id=str(uuid.uuid4()), profile_id=profile.id, target_entity=target, steps=steps)
