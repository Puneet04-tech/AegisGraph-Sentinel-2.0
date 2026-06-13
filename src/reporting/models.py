"""Enterprise Reporting Models"""
from __future__ import annotations
from datetime import datetime, timezone  # noqa: F401
from typing import Any, Dict, List, Optional  # noqa: F401
from pydantic import BaseModel, Field
import uuid


class Report(BaseModel):
    """Report."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    report_type: str
    content: Dict[str, Any] = {}
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReportTemplate(BaseModel):
    """Report template."""
    template_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    report_type: str
    config: Dict[str, Any] = {}


class ReportSchedule(BaseModel):
    """Report schedule."""
    schedule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    template_id: str
    frequency: str
    enabled: bool = True


class ReportingMetrics(BaseModel):
    """Reporting metrics."""
    total_reports: int = 0
    templates: int = 0
    scheduled_reports: int = 0
