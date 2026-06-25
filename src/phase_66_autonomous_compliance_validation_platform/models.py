from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime


@dataclass
class ComplianceValidationPlatformCompliancePolicy:
    record_id: str
    tenant_id: str
    policy_id: str
    regulation_name: str
    rules_count: int
    status: str
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class ComplianceValidationPlatformControlAssessment:
    record_id: str
    tenant_id: str
    assessment_id: str
    control_id: str
    compliance_percentage: float
    findings: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class ComplianceValidationPlatformComplianceAudit:
    record_id: str
    tenant_id: str
    audit_id: str
    auditor_name: str
    violations_detected: int
    audit_date: str
    created_at: datetime = field(default_factory=datetime.utcnow)
