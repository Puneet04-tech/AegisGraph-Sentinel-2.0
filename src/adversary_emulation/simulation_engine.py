from datetime import datetime
from .models import AttackCampaign, SimulationResult

class SimulationEngine:
    def execute(self, campaign: AttackCampaign) -> SimulationResult:
        detected = 0
        for step in campaign.steps:
            step.status = "EXECUTED"
            detected += 1
        return SimulationResult(
            campaign_id=campaign.id,
            success_rate=1.0 if len(campaign.steps) > 0 else 0.0,
            detected_steps=detected,
            total_steps=len(campaign.steps),
            timestamp=datetime.utcnow()
        )
