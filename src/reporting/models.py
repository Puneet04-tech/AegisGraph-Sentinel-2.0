"""Reporting Models"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

class ReportType(Enum):
    """Report types"""
    EXECUTIVE = "EXECUTIVE"
    OPERATIONAL = "OPERATIONAL"
    COMPLIANCE = "COMPLIANCE"
    AUDIT = "AUDIT"
    INVESTIGATION = "INVESTIGATION"

class ReportStatus(Enum):
    """Report status"""
    DRAFT = "DRAFT"
    GENERATED = "GENERATED"
    REVIEWED = "REVIEWED"
    ARCHIVED = "ARCHIVED"

@dataclass
class Report:
    """Report definition"""
    report_id: str
    name: str
    report_type: ReportType
    description: str
    parameters: Dict[str, Any]
    status: ReportStatus
    generated_at: Optional[datetime] = None
    created_by: str = "system"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "name": self.name,
            "report_type": self.report_type.value,
            "description": self.description,
            "parameters": self.parameters,
            "status": self.status.value,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
            "created_by": self.created_by
        }

@dataclass
class ReportTemplate:
    """Report template"""
    template_id: str
    name: str
    report_type: ReportType
    description: str
    content_template: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "report_type": self.report_type.value,
            "description": self.description,
            "content_template": self.content_template
        }