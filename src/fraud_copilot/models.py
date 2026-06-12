"""
Fraud Analyst Copilot Models.

AI-powered copilot models for fraud analysis assistance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class MessageRole(str, Enum):
    """Message roles in conversation."""
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


class RecommendationType(str, Enum):
    """Types of recommendations."""
    INVESTIGATION = "investigation"
    ESCALATION = "escalation"
    CLOSURE = "closure"
    ENHANCED_MONITORING = "enhanced_monitoring"
    THREAT_HUNTING = "threat_hunting"


class InsightType(str, Enum):
    """Types of investigation insights."""
    PATTERN = "pattern"
    ANOMALY = "anomaly"
    CORRELATION = "correlation"
    ATTRIBUTION = "attribution"


@dataclass
class ConversationMessage:
    """A message in a copilot session."""
    message_id: str
    role: MessageRole
    content: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CopilotSession:
    """A copilot session for an investigation."""
    session_id: str
    user_id: str
    case_id: Optional[str] = None
    messages: List[ConversationMessage] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    active: bool = True


@dataclass
class CaseSummary:
    """AI-generated case summary."""
    summary_id: str
    case_id: str
    summary_text: str
    key_findings: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    confidence: float = 0.8
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ThreatExplanation:
    """Explanation of a threat or attack."""
    explanation_id: str
    case_id: str
    topic: str
    explanation_text: str
    attack_chain: List[Dict[str, Any]] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    confidence: float = 0.8
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Recommendation:
    """Investigation recommendation."""
    recommendation_id: str
    case_id: str
    recommendation_type: RecommendationType
    title: str
    description: str
    priority: int = 1
    confidence: float = 0.8
    supporting_evidence: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class InvestigationInsight:
    """Insight discovered during investigation."""
    insight_id: str
    case_id: str
    insight_type: InsightType
    title: str
    description: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.8
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class KnowledgeDocument:
    """Knowledge document for search."""
    document_id: str
    title: str
    content: str
    category: str
    tags: List[str] = field(default_factory=list)
    relevance_scores: Dict[str, float] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ReportSection:
    """Section of a generated report."""
    section_id: str
    title: str
    content: str
    subsections: List['ReportSection'] = field(default_factory=list)


@dataclass
class GeneratedReport:
    """AI-generated investigation report."""
    report_id: str
    case_id: str
    title: str
    sections: List[ReportSection] = field(default_factory=list)
    executive_summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DecisionSupport:
    """Decision support analysis."""
    decision_id: str
    case_id: str
    decision_options: List[Dict[str, Any]]
    recommended_option: int
    reasoning: str
    risk_assessment: Dict[str, float] = field(default_factory=dict)
    confidence: float = 0.8
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AuditEvent:
    """Audit event for copilot operations."""
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    session_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True