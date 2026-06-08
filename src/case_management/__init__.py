"""Case Management module for AegisGraph Sentinel 2.0.

Provides fraud case lifecycle management, analyst assignment,
evidence tracking, and immutable audit trail capabilities.
"""

from .models import (
    CaseStatus,
    CasePriority,
    EvidenceType,
    FraudCase,
    CaseComment,
    CaseEvidence,
    CaseAuditEvent,
)
from .store import CaseStore, get_case_store

__all__ = [
    "CaseStatus",
    "CasePriority",
    "EvidenceType",
    "FraudCase",
    "CaseComment",
    "CaseEvidence",
    "CaseAuditEvent",
    "CaseStore",
    "get_case_store",
]
