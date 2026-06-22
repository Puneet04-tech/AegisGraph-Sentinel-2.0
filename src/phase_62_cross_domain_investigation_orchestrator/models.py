from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class InvestigationOrchestratorInvestigationWorkflow:
    record_id: str
    tenant_id: str
    workflow_id: str
    domain: str
    current_state: str
    assigned_analyst: str
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class InvestigationOrchestratorEvidenceCorrelation:
    record_id: str
    tenant_id: str
    correlation_id: str
    evidence_ids: List[str]
    score: float
    description: str
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class InvestigationOrchestratorEscalationRecord:
    record_id: str
    tenant_id: str
    escalation_id: str
    reason: str
    priority: str
    resolved: bool
    created_at: datetime = field(default_factory=datetime.utcnow)
