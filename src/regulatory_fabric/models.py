"""
Data models for Regulatory Intelligence & Compliance Fabric.

Core models:
    Regulation: Regulatory requirement model
    Control: Security control model
    Policy: Internal policy model
    ComplianceAssessment: Compliance assessment result
    AuditEvidence: Audit evidence record
    ComplianceRisk: Compliance risk assessment
    ControlMapping: Mapping between regulations and controls
    RegulatoryUpdate: Regulatory change tracking
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
import uuid


class RegulationDomain(str, Enum):
    """Regulatory domains."""
    PCI_DSS = "PCI_DSS"
    SOC2 = "SOC2"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    SOX = "SOX"
    ISO27001 = "ISO27001"
    NIST_CSF = "NIST_CSF"
    FINRA = "FINRA"
    CCPA = "CCPA"
    FEDRAMP = "FEDRAMP"
    GLBA = "GLBA"
    CUSTOM = "CUSTOM"


class RegulationStatus(str, Enum):
    """Regulation status."""
    ACTIVE = "ACTIVE"
    PENDING = "PENDING"
    SUPERSEDED = "SUPERSEDED"
    RETIRED = "RETIRED"


class ControlStatus(str, Enum):
    """Control implementation status."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNDER_REVIEW = "UNDER_REVIEW"


class ControlEffectiveness(str, Enum):
    """Control effectiveness level."""
    EFFECTIVE = "EFFECTIVE"
    NEEDS_IMPROVEMENT = "NEEDS_IMPROVEMENT"
    INEFFECTIVE = "INEFFECTIVE"
    UNKNOWN = "UNKNOWN"


class AssessmentStatus(str, Enum):
    """Assessment status."""
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class EvidenceStatus(str, Enum):
    """Evidence collection status."""
    PENDING = "PENDING"
    COLLECTED = "COLLECTED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class RiskLevel(str, Enum):
    """Compliance risk levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


@dataclass
class Regulation:
    """Regulatory requirement model.
    
    Attributes:
        regulation_id: Unique identifier
        domain: Regulatory domain
        name: Regulation name
        version: Regulation version
        effective_date: When regulation becomes effective
        status: Current status
        description: Regulation description
        requirements: List of specific requirements
        penalties: Associated penalties for non-compliance
        metadata: Additional metadata
    """
    regulation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    domain: RegulationDomain = RegulationDomain.PCI_DSS
    name: str = ""
    version: str = "1.0"
    effective_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    status: RegulationStatus = RegulationStatus.ACTIVE
    description: str = ""
    requirements: List[Dict[str, Any]] = field(default_factory=list)
    penalties: Dict[str, Any] = field(default_factory=dict)
    source_url: Optional[str] = None
    last_reviewed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "regulation_id": self.regulation_id,
            "domain": self.domain.value,
            "name": self.name,
            "version": self.version,
            "effective_date": self.effective_date.isoformat() if self.effective_date else None,
            "expiry_date": self.expiry_date.isoformat() if self.expiry_date else None,
            "status": self.status.value,
            "description": self.description,
            "requirements": self.requirements,
            "penalties": self.penalties,
            "source_url": self.source_url,
            "last_reviewed": self.last_reviewed.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class Control:
    """Security control model.
    
    Attributes:
        control_id: Unique identifier
        control_name: Control name
        control_number: Control reference number
        description: Control description
        category: Control category
        implementation: Implementation details
        status: Current status
        effectiveness: Effectiveness assessment
        owner: Control owner
        last_tested: Last test date
        next_test: Next test due date
    """
    control_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    control_name: str = ""
    control_number: Optional[str] = None
    description: str = ""
    category: str = ""
    implementation: str = ""
    status: ControlStatus = ControlStatus.UNDER_REVIEW
    effectiveness: ControlEffectiveness = ControlEffectiveness.UNKNOWN
    owner: str = ""
    last_tested: Optional[datetime] = None
    next_test: Optional[datetime] = None
    test_frequency_days: int = 90
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "control_number": self.control_number,
            "description": self.description,
            "category": self.category,
            "implementation": self.implementation,
            "status": self.status.value,
            "effectiveness": self.effectiveness.value,
            "owner": self.owner,
            "last_tested": self.last_tested.isoformat() if self.last_tested else None,
            "next_test": self.next_test.isoformat() if self.next_test else None,
            "test_frequency_days": self.test_frequency_days,
            "metadata": self.metadata,
        }


@dataclass
class Policy:
    """Internal policy model.
    
    Attributes:
        policy_id: Unique identifier
        name: Policy name
        version: Policy version
        domain: Related regulatory domain
        description: Policy description
        scope: Policy scope
        owner: Policy owner
        approval_date: When policy was approved
        review_date: Next review date
        status: Policy status
    """
    policy_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    version: str = "1.0"
    domain: Optional[RegulationDomain] = None
    description: str = ""
    scope: str = ""
    owner: str = ""
    approval_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    status: str = "DRAFT"
    related_controls: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "version": self.version,
            "domain": self.domain.value if self.domain else None,
            "description": self.description,
            "scope": self.scope,
            "owner": self.owner,
            "approval_date": self.approval_date.isoformat() if self.approval_date else None,
            "review_date": self.review_date.isoformat() if self.review_date else None,
            "status": self.status,
            "related_controls": self.related_controls,
            "metadata": self.metadata,
        }


@dataclass
class ControlMapping:
    """Mapping between regulations and controls.
    
    Attributes:
        mapping_id: Unique identifier
        regulation_id: Regulation ID
        control_id: Control ID
        requirement_id: Specific requirement ID
        mapping_type: Type of mapping (DIRECT, PARTIAL, INDIRECT)
        justification: Mapping justification
        confidence: Confidence in mapping
    """
    mapping_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    regulation_id: str = ""
    control_id: str = ""
    requirement_id: Optional[str] = None
    mapping_type: str = "DIRECT"
    justification: str = ""
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mapping_id": self.mapping_id,
            "regulation_id": self.regulation_id,
            "control_id": self.control_id,
            "requirement_id": self.requirement_id,
            "mapping_type": self.mapping_type,
            "justification": self.justification,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass
class ComplianceAssessment:
    """Compliance assessment result.
    
    Attributes:
        assessment_id: Unique identifier
        regulation_id: Regulation being assessed
        assessment_date: When assessment was performed
        status: Assessment status
        overall_score: Overall compliance score (0-100)
        controls_assessed: Number of controls assessed
        controls_passed: Number of controls passed
        controls_failed: Number of controls failed
        findings: List of findings
        assessor: Who performed assessment
        next_assessment: Next scheduled assessment
    """
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    regulation_id: str = ""
    assessment_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: AssessmentStatus = AssessmentStatus.COMPLETED
    overall_score: float = 0.0
    controls_assessed: int = 0
    controls_passed: int = 0
    controls_failed: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_exposure: float = 0.0
    assessor: str = "SYSTEM"
    next_assessment: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "assessment_id": self.assessment_id,
            "regulation_id": self.regulation_id,
            "assessment_date": self.assessment_date.isoformat(),
            "status": self.status.value,
            "overall_score": self.overall_score,
            "controls_assessed": self.controls_assessed,
            "controls_passed": self.controls_passed,
            "controls_failed": self.controls_failed,
            "findings": self.findings,
            "risk_exposure": self.risk_exposure,
            "assessor": self.assessor,
            "next_assessment": self.next_assessment.isoformat() if self.next_assessment else None,
            "metadata": self.metadata,
        }


@dataclass
class AuditEvidence:
    """Audit evidence record.
    
    Attributes:
        evidence_id: Unique identifier
        control_id: Related control ID
        assessment_id: Related assessment ID
        evidence_type: Type of evidence
        description: Evidence description
        collection_date: When evidence was collected
        status: Evidence status
        source_system: Source system for evidence
        captured_data: Evidence data
        verified_by: Who verified evidence
        verified_at: When verification occurred
    """
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    control_id: str = ""
    assessment_id: Optional[str] = None
    evidence_type: str = ""
    description: str = ""
    collection_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expiry_date: Optional[datetime] = None
    status: EvidenceStatus = EvidenceStatus.COLLECTED
    source_system: str = ""
    captured_data: Dict[str, Any] = field(default_factory=dict)
    verified_by: Optional[str] = None
    verified_at: Optional[datetime] = None
    retention_days: int = 365
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "control_id": self.control_id,
            "assessment_id": self.assessment_id,
            "evidence_type": self.evidence_type,
            "description": self.description,
            "collection_date": self.collection_date.isoformat(),
            "expiry_date": self.expiry_date.isoformat() if self.expiry_date else None,
            "status": self.status.value,
            "source_system": self.source_system,
            "captured_data": self.captured_data,
            "verified_by": self.verified_by,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "retention_days": self.retention_days,
            "metadata": self.metadata,
        }


@dataclass
class ComplianceRisk:
    """Compliance risk assessment.
    
    Attributes:
        risk_id: Unique identifier
        regulation_id: Related regulation
        control_id: Related control
        risk_level: Risk severity level
        description: Risk description
        likelihood: Probability of occurrence (0-1)
        impact: Potential impact (0-1)
        mitigation_status: Current mitigation status
        mitigation_plan: Mitigation plan details
        owner: Risk owner
        identified_date: When risk was identified
        target_resolution: Target resolution date
    """
    risk_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    regulation_id: Optional[str] = None
    control_id: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.MEDIUM
    description: str = ""
    likelihood: float = 0.5
    impact: float = 0.5
    risk_score: float = 0.25
    mitigation_status: str = "OPEN"
    mitigation_plan: str = ""
    owner: str = ""
    identified_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    target_resolution: Optional[datetime] = None
    actual_resolution: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Calculate risk score."""
        self.risk_score = self.likelihood * self.impact

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "risk_id": self.risk_id,
            "regulation_id": self.regulation_id,
            "control_id": self.control_id,
            "risk_level": self.risk_level.value,
            "description": self.description,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.risk_score,
            "mitigation_status": self.mitigation_status,
            "mitigation_plan": self.mitigation_plan,
            "owner": self.owner,
            "identified_date": self.identified_date.isoformat(),
            "target_resolution": self.target_resolution.isoformat() if self.target_resolution else None,
            "actual_resolution": self.actual_resolution.isoformat() if self.actual_resolution else None,
            "metadata": self.metadata,
        }


@dataclass
class RegulatoryUpdate:
    """Regulatory change tracking.
    
    Attributes:
        update_id: Unique identifier
        regulation_id: Related regulation
        update_type: Type of update
        title: Update title
        summary: Update summary
        effective_date: When changes take effect
        published_date: When update was published
        source: Source of update
        affected_requirements: List of affected requirements
        compliance_impact: Estimated compliance impact
        recommended_actions: Recommended actions
    """
    update_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    regulation_id: str = ""
    update_type: str = "AMENDMENT"
    title: str = ""
    summary: str = ""
    effective_date: Optional[datetime] = None
    published_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""
    source_url: Optional[str] = None
    affected_requirements: List[str] = field(default_factory=list)
    compliance_impact: str = "MEDIUM"
    recommended_actions: List[str] = field(default_factory=list)
    processed: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "update_id": self.update_id,
            "regulation_id": self.regulation_id,
            "update_type": self.update_type,
            "title": self.title,
            "summary": self.summary,
            "effective_date": self.effective_date.isoformat() if self.effective_date else None,
            "published_date": self.published_date.isoformat(),
            "source": self.source,
            "source_url": self.source_url,
            "affected_requirements": self.affected_requirements,
            "compliance_impact": self.compliance_impact,
            "recommended_actions": self.recommended_actions,
            "processed": self.processed,
            "metadata": self.metadata,
        }


@dataclass
class ComplianceDashboard:
    """Executive compliance dashboard data.
    
    Attributes:
        dashboard_id: Unique identifier
        generated_at: When dashboard was generated
        overall_score: Overall compliance score
        domain_scores: Scores by regulation domain
        open_findings: Number of open findings
        critical_findings: Number of critical findings
        recent_assessments: Recent assessment summaries
        upcoming_deadlines: Upcoming compliance deadlines
        risk_summary: Risk summary by level
    """
    dashboard_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    overall_score: float = 0.0
    domain_scores: Dict[str, float] = field(default_factory=dict)
    open_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    recent_assessments: List[Dict[str, Any]] = field(default_factory=list)
    upcoming_deadlines: List[Dict[str, Any]] = field(default_factory=list)
    risk_summary: Dict[str, int] = field(default_factory=dict)
    trend_direction: str = "STABLE"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "dashboard_id": self.dashboard_id,
            "generated_at": self.generated_at.isoformat(),
            "overall_score": self.overall_score,
            "domain_scores": self.domain_scores,
            "open_findings": self.open_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "recent_assessments": self.recent_assessments,
            "upcoming_deadlines": self.upcoming_deadlines,
            "risk_summary": self.risk_summary,
            "trend_direction": self.trend_direction,
            "metadata": self.metadata,
        }