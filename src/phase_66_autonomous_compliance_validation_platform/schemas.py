from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class ComplianceValidationPlatformCompliancePolicyCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    policy_id: str = Field(..., description="policy_id attribute")
    regulation_name: str = Field(..., description="regulation_name attribute")
    rules_count: int = Field(..., description="rules_count attribute")
    status: str = Field(..., description="status attribute")

class ComplianceValidationPlatformControlAssessmentCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    assessment_id: str = Field(..., description="assessment_id attribute")
    control_id: str = Field(..., description="control_id attribute")
    compliance_percentage: float = Field(..., description="compliance_percentage attribute")
    findings: List[str] = Field(..., description="findings attribute")

class ComplianceValidationPlatformComplianceAuditCreateSchema(BaseModel):
    record_id: str = Field(..., description="Unique record identifier")
    tenant_id: str = Field(..., description="Associated tenant workspace")
    audit_id: str = Field(..., description="audit_id attribute")
    auditor_name: str = Field(..., description="auditor_name attribute")
    violations_detected: int = Field(..., description="violations_detected attribute")
    audit_date: str = Field(..., description="audit_date attribute")
