"""Campaign Generator Module

Generates attack campaign step sequences from adversary profiles.
"""
import uuid
from .models import AdversaryProfile, AttackCampaign, SimulationStep


class CampaignGenerator:
    """Generates structured attack campaigns from adversary profiles.

    Takes an AdversaryProfile containing tactics and techniques, then produces
    an AttackCampaign with individual SimulationSteps ready for execution.
    """

    def generate(self, profile: AdversaryProfile, target: str) -> AttackCampaign:
        """Generate an attack campaign for a given adversary profile.

        Args:
            profile: The adversary profile defining tactics and techniques.
            target: The target entity to attack.

        Returns:
            An AttackCampaign with SimulationSteps for each tactic.
        """
        steps = [
            SimulationStep(step_id=str(uuid.uuid4()), tactic=t, technique="Simulated", status="PENDING")
            for t in profile.tactics
        ]
        return AttackCampaign(id=str(uuid.uuid4()), profile_id=profile.id, target_entity=target, steps=steps)
