"""Simulation Engine Module

Executes attack campaign simulations and produces structured results.
"""
from datetime import datetime, timezone
from typing import Callable, Optional

from .models import AttackCampaign, SimulationResult, SimulationStep


class SimulationEngine:
    """Engine for executing adversary attack campaigns.

    The SimulationEngine is responsible for running red-team attack campaigns
    against a target environment. Each step in an AttackCampaign is evaluated
    honestly and the aggregate metrics (success rate, detected steps) are
    derived from the per-step outcomes.

    Outcomes are produced by an injected outcome evaluator. When no evaluator
    is configured (i.e. no real target-environment probes are available), the
    engine reports every step as ``NOT_EXECUTED`` with ``validated=False``
    instead of fabricating perfect success and detection numbers.

    Usage:
        engine = SimulationEngine()
        result = engine.execute(campaign)

    Attributes:
        outcome_evaluator: Optional callable accepting a SimulationStep and
            returning a mapping with ``status``, ``success`` and ``detected``
            keys. When omitted, simulations are reported as not validated.
    """

    def __init__(self, outcome_evaluator: Optional[Callable[[SimulationStep], dict]] = None):
        self._outcome_evaluator = outcome_evaluator

    def execute(self, campaign: AttackCampaign) -> SimulationResult:
        """Execute all steps in an attack campaign.

        Args:
            campaign: The AttackCampaign to execute.

        Returns:
            A SimulationResult containing execution metrics.
        """
        if self._outcome_evaluator is None:
            return self._execute_not_validated(campaign)
        return self._execute_validated(campaign)

    def _execute_not_validated(self, campaign: AttackCampaign) -> SimulationResult:
        """Report a simulation that was not actually executed or validated."""
        for step in campaign.steps:
            step.status = "NOT_EXECUTED"
            step.success = False
            step.detected = False
        return SimulationResult(
            campaign_id=campaign.id,
            success_rate=0.0,
            detected_steps=0,
            total_steps=len(campaign.steps),
            validated=False,
            timestamp=datetime.now(timezone.utc),
        )

    def _execute_validated(self, campaign: AttackCampaign) -> SimulationResult:
        """Evaluate each step through the configured outcome evaluator."""
        succeeded = 0
        detected = 0
        for step in campaign.steps:
            outcome = self._outcome_evaluator(step)
            step.status = outcome.get("status", "EXECUTED")
            step.success = bool(outcome.get("success", False))
            step.detected = bool(outcome.get("detected", False))
            if step.success:
                succeeded += 1
            if step.detected:
                detected += 1

        total_steps = len(campaign.steps)
        return SimulationResult(
            campaign_id=campaign.id,
            success_rate=(succeeded / total_steps) if total_steps > 0 else 0.0,
            detected_steps=detected,
            total_steps=total_steps,
            validated=True,
            timestamp=datetime.now(timezone.utc),
        )
