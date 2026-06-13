"""Sovereign Federation Module
National Intelligence Federation for AegisGraph.
Secure cross-border intelligence sharing with sovereignty controls.
"""
from .models import (
    NationalEntity, GovernancePolicy, IntelligenceShare, ComplianceRecord,
    FederationRole, DataClassification, ComplianceStatus
)
from .service import SovereignFederationService, get_sovereign_federation_service

__all__ = [
    "NationalEntity",
    "GovernancePolicy",
    "IntelligenceShare",
    "ComplianceRecord",
    "FederationRole",
    "DataClassification",
    "ComplianceStatus",
    "SovereignFederationService",
    "get_sovereign_federation_service"
]