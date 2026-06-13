"""Advanced Forensics & Investigation Models"""
from __future__ import annotations
from datetime import datetime, timezone  # noqa: F401
from typing import Any, Dict, List, Optional  # noqa: F401
from pydantic import BaseModel, Field
import uuid


class Investigation(BaseModel):
    """Investigation case."""
    investigation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    status: str = "OPEN"
    priority: str = "MEDIUM"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Evidence(BaseModel):
    """Evidence item."""
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str
    evidence_type: str
    content: Dict[str, Any] = {}
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ForensicReport(BaseModel):
    """Forensic analysis report."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str
    findings: List[str] = []
    recommendations: List[str] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ChainOfCustody(BaseModel):
    """Chain of custody record."""
    custody_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_id: str
    custodian: str
    action: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ForensicsMetrics(BaseModel):
    """Forensics metrics."""
    total_investigations: int = 0
    open_cases: int = 0
    evidence_items: int = 0
