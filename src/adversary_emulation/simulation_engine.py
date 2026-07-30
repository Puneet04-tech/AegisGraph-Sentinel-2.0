"""Simulation Engine Module

Executes attack campaign simulations and produces structured results.
"""
from datetime import datetime, timezone
from .models import AttackCampaign, SimulationResult


class SimulationEngine:
    """Engine for executing adversary attack campaigns.

    Marks each simulation step as executed and computes aggregate metrics
    including success rate and detection counts.
    """

    def execute(self, campaign: AttackCampaign) -> SimulationResult:
        """Execute all steps in an attack campaign.

        Args:
            campaign: The AttackCampaign to execute.

        Returns:
            A SimulationResult containing execution metrics.
        """
        detected = 0
        for step in campaign.steps:
            step.status = "EXECUTED"
            detected += 1
        return SimulationResult(
            campaign_id=campaign.id,
            success_rate=1.0 if len(campaign.steps) > 0 else 0.0,
            detected_steps=detected,
            total_steps=len(campaign.steps),
            timestamp=datetime.now(timezone.utc)
        )
