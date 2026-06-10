"""
AI Red Team & Adversarial Fraud Simulator.

Simulates fraud attacks and adversarial scenarios to test model robustness.
"""

import random
from typing import Dict, List, Optional
from datetime import datetime, timezone

from .models import (
    AttackType,
    AttackResult,
    CampaignResult,
    AdversarialSample,
)


class AdversarialSimulator:
    """Adversarial Simulator for red team campaigns.
    
    Provides:
        - Fraud attack simulation
        - Adversarial testing
        - Model robustness validation
        - Red team campaigns
    """
    
    def __init__(self):
        self._attack_history: List[AttackResult] = []
        self._campaign_history: List[CampaignResult] = []
    
    def simulate_attack(
        self,
        attack_type: AttackType,
        target_model: str,
        original_features: Dict[str, float],
    ) -> AttackResult:
        """Simulate an adversarial attack."""
        # Simulate perturbation
        perturbed = self._add_adversarial_perturbation(original_features)
        
        # Calculate evasion rate
        evasion_rate = random.uniform(0.1, 0.9)
        success = evasion_rate > 0.5
        
        result = AttackResult(
            attack_type=attack_type,
            target_model=target_model,
            success=success,
            evasion_rate=evasion_rate,
            detection_avoided=success,
        )
        
        self._attack_history.append(result)
        return result
    
    def _add_adversarial_perturbation(
        self,
        features: Dict[str, float],
    ) -> Dict[str, float]:
        """Add adversarial perturbation to features."""
        perturbed = features.copy()
        for key in perturbed:
            perturbation = random.uniform(-0.1, 0.1) * perturbed[key]
            perturbed[key] = perturbed[key] + perturbation
        return perturbed
    
    def run_campaign(
        self,
        campaign_name: str,
        target_model: str,
        num_attacks: int = 10,
    ) -> CampaignResult:
        """Run a red team campaign."""
        attack_types = list(AttackType)
        results = []
        
        for _ in range(num_attacks):
            attack_type = random.choice(attack_types)
            features = {"feature1": random.uniform(0, 1), "feature2": random.uniform(0, 1)}
            result = self.simulate_attack(attack_type, target_model, features)
            results.append(result)
        
        success_rate = sum(1 for r in results if r.success) / len(results)
        
        campaign = CampaignResult(
            campaign_name=campaign_name,
            attack_results=results,
            overall_success_rate=success_rate,
            vulnerabilities_found=self._identify_vulnerabilities(results),
            recommendations=self._generate_recommendations(success_rate),
        )
        
        self._campaign_history.append(campaign)
        return campaign
    
    def _identify_vulnerabilities(self, results: List[AttackResult]) -> List[str]:
        """Identify vulnerabilities found."""
        vulnerabilities = []
        if any(r.attack_type == AttackType.EVASION and r.success for r in results):
            vulnerabilities.append("Model vulnerable to evasion attacks")
        if any(r.attack_type == AttackType.ADVERSARIAL_PERTURBATION and r.success for r in results):
            vulnerabilities.append("Model vulnerable to adversarial perturbations")
        return vulnerabilities
    
    def _generate_recommendations(self, success_rate: float) -> List[str]:
        """Generate recommendations based on results."""
        if success_rate > 0.5:
            return [
                "Consider adversarial training",
                "Implement input validation",
                "Enhance feature preprocessing",
            ]
        return ["Continue monitoring for new attack vectors"]
    
    def get_campaign_history(self) -> List[CampaignResult]:
        """Get campaign history."""
        return self._campaign_history

import threading
from threading import Lock

_simulator: Optional[AdversarialSimulator] = None
_simulator_lock = Lock()


def get_adversarial_simulator() -> AdversarialSimulator:
    global _simulator
    with _simulator_lock:
        if _simulator is None:
            _simulator = AdversarialSimulator()
        return _simulator