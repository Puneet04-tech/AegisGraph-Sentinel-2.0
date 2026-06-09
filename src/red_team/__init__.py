"""
AI Red Team & Adversarial Fraud Simulator.

A production-grade module for fraud attack simulation
and model robustness validation.
"""

from .models import (
    AttackType,
    AttackResult,
    CampaignResult,
    AdversarialSample,
)
from .simulator import AdversarialSimulator, get_adversarial_simulator

__all__ = [
    "AttackType",
    "AttackResult",
    "CampaignResult",
    "AdversarialSample",
    "AdversarialSimulator",
    "get_adversarial_simulator",
]