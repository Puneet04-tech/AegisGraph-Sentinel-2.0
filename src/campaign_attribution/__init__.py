"""
Campaign Attribution Platform

Enterprise-scale fraud campaign attribution system for AegisGraph Sentinel 2.0.
Discovers, correlates, and attributes fraud campaigns, attacker infrastructure,
threat actors, and criminal networks.
"""

from .models import (
    ThreatActor,
    Campaign,
    Attribution,
    ThreatProfile,
    AttackPattern,
    RiskAssessment,
    Infrastructure,
)
from .store import get_campaign_store
from .service import get_campaign_service

__all__ = [
    "ThreatActor",
    "Campaign",
    "Attribution",
    "ThreatProfile",
    "AttackPattern",
    "RiskAssessment",
    "Infrastructure",
    "get_campaign_store",
    "get_campaign_service",
]
