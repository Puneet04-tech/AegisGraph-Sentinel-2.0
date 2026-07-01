from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class SecurityGovernanceCommandCenterModelGovernanceRecord:
    record_id: str
    tenant_id: str
    model_id: str
    model_version: str
    bias_score: float
    is_approved: bool
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityGovernanceCommandCenterPromptAuditRecord:
    record_id: str
    tenant_id: str
    audit_id: str
    prompt_hash: str
    risk_level: str
    policy_violations: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class SecurityGovernanceCommandCenterRiskMonitorState:
    record_id: str
    tenant_id: str
    state_id: str
    total_governed_models: int
    anomalies_count: int
    last_checked: str
    created_at: datetime = field(default_factory=datetime.utcnow)
