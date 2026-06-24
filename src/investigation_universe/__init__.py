"""Investigation Universe Module
AI Investigation Universe for AegisGraph.
Autonomous investigation with evidence correlation and hypothesis generation.
"""
from .models import (
    Investigation, Evidence, Hypothesis, Correlation,
    InvestigationStatus, EvidenceType, ConfidenceLevel
)
from .service import InvestigationUniverseService, get_investigation_service

__all__ = [
    "Investigation",
    "Evidence",
    "Hypothesis",
    "Correlation",
    "InvestigationStatus",
    "EvidenceType",
    "ConfidenceLevel",
    "InvestigationUniverseService",
    "get_investigation_service"
]