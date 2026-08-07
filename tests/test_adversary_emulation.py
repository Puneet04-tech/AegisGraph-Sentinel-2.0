from src.adversary_emulation.models import (
    AdversaryProfile,
    AttackCampaign,
    SimulationStep,
)
from src.adversary_emulation.service import AdversaryEmulationService
from src.adversary_emulation.simulation_engine import SimulationEngine

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


def _campaign_with_steps():
    return AttackCampaign(
        id="campaign-1",
        profile_id="profile-1",
        target_entity="target-corp",
        steps=[
            SimulationStep(step_id="s1", tactic="Reconnaissance", technique="Phishing"),
            SimulationStep(step_id="s2", tactic="Initial Access", technique="Credential Dumping"),
        ],
    )


def test_simulation_without_evaluator_is_not_validated():
    """Without an outcome evaluator the engine must not fabricate results."""
    engine = SimulationEngine()
    campaign = _campaign_with_steps()

    result = engine.execute(campaign)

    assert result.total_steps == 2
    assert result.success_rate == 0.0
    assert result.detected_steps == 0
    assert result.validated is False
    assert all(step.status == "NOT_EXECUTED" for step in campaign.steps)
    assert all(step.success is False for step in campaign.steps)
    assert all(step.detected is False for step in campaign.steps)


def test_simulation_with_evaluator_reports_honest_outcomes():
    """A non-zero success_rate and detected_steps < total_steps are reachable."""
    def evaluator(step):
        if step.step_id == "s1":
            return {"status": "EXECUTED", "success": True, "detected": False}
        return {"status": "EXECUTED", "success": False, "detected": True}

    engine = SimulationEngine(outcome_evaluator=evaluator)
    campaign = _campaign_with_steps()

    result = engine.execute(campaign)

    assert result.total_steps == 2
    assert result.validated is True
    assert result.success_rate == 0.5
    assert result.detected_steps == 1
    assert [step.status for step in campaign.steps] == ["EXECUTED", "EXECUTED"]
    assert [step.success for step in campaign.steps] == [True, False]
    assert [step.detected for step in campaign.steps] == [False, True]

