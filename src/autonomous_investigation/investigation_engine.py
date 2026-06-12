"""
Investigation Engine for autonomous fraud investigation orchestration.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    InvestigationCase,
    InvestigationStatus,
    CasePriority,
    SeverityLevel,
    EvidenceArtifact,
    EvidenceType,
)
from .store import InvestigationStore, get_investigation_store
from .evidence_collector import EvidenceCollector, get_evidence_collector
from .decision_engine import DecisionIntelligenceEngine, get_decision_engine
from .explainability import ExplainabilityEngine, get_explainability_engine


class InvestigationEngine:
    """
    Orchestrates autonomous fraud investigations.

    Handles:
    - Investigation case lifecycle management
    - Evidence collection coordination
    - Analysis pipeline orchestration
    - Decision generation
    - Report creation
    """

    def __init__(
        self,
        store: Optional[InvestigationStore] = None,
        evidence_collector: Optional[EvidenceCollector] = None,
        decision_engine: Optional[DecisionIntelligenceEngine] = None,
        explainability: Optional[ExplainabilityEngine] = None,
    ):
        self._store = store or get_investigation_store()
        self._evidence = evidence_collector or get_evidence_collector()
        self._decision = decision_engine or get_decision_engine()
        self._explainability = explainability or get_explainability_engine()

    def create_investigation(
        self,
        title: str,
        description: str,
        alert_ids: Optional[List[str]] = None,
        entity_ids: Optional[List[str]] = None,
        priority: CasePriority = CasePriority.P2_MEDIUM,
        initial_risk_score: float = 0.5,
    ) -> InvestigationCase:
        """Create a new investigation case."""
        case_id = str(uuid.uuid4())

        case = InvestigationCase(
            case_id=case_id,
            title=title,
            description=description,
            status=InvestigationStatus.CREATED,
            priority=priority,
            severity=SeverityLevel.MODERATE,
            alert_ids=alert_ids or [],
            entity_ids=entity_ids or [],
            risk_score=initial_risk_score,
            confidence_score=0.0,
        )

        self._store.store_case(case)
        self._log_operation("investigation_create", case_id, {"title": title})

        return case

    async def start_investigation(self, case_id: str) -> InvestigationCase:
        """Start an investigation."""
        case = self._store.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        case.status = InvestigationStatus.IN_PROGRESS
        case.started_at = datetime.now(timezone.utc)
        case.updated_at = datetime.now(timezone.utc)

        self._store.store_case(case)
        self._log_operation("investigation_start", case_id, {})

        return case

    async def collect_evidence(
        self,
        case_id: str,
        evidence_types: Optional[List[EvidenceType]] = None,
    ) -> List[EvidenceArtifact]:
        """Collect evidence for a case."""
        case = self._store.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        # Collect evidence from all sources
        evidence = await self._evidence.collect_evidence(
            entity_ids=case.entity_ids,
            alert_ids=case.alert_ids,
            evidence_types=evidence_types,
        )

        # Link evidence to case
        for artifact in evidence:
            self._store.store_evidence(artifact)
            self._store.link_evidence_to_case(case_id, artifact.evidence_id)

        case.status = InvestigationStatus.EVIDENCE_COLLECTED
        case.updated_at = datetime.now(timezone.utc)
        self._store.store_case(case)

        self._log_operation("evidence_collected", case_id, {
            "evidence_count": len(evidence),
        })

        return evidence

    async def analyze_investigation(
        self, case_id: str
    ) -> Dict[str, Any]:
        """Perform comprehensive analysis of an investigation."""
        case = self._store.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        case.status = InvestigationStatus.ANALYZING
        case.updated_at = datetime.now(timezone.utc)
        self._store.store_case(case)

        # Get evidence
        evidence = self._store.get_evidence_for_case(case_id)

        # Perform analysis
        analysis_result = await self._perform_analysis(case, evidence)

        # Update case
        case.findings = analysis_result["findings"]
        case.patterns_detected = analysis_result["patterns"]
        case.correlations_found = analysis_result["correlations_count"]
        case.risk_score = analysis_result["risk_score"]
        case.confidence_score = analysis_result["confidence"]
        case.severity = self._calculate_severity(analysis_result["risk_score"])
        case.updated_at = datetime.now(timezone.utc)

        self._store.store_case(case)

        self._log_operation("investigation_analyzed", case_id, {
            "findings_count": len(analysis_result["findings"]),
            "patterns_count": len(analysis_result["patterns"]),
        })

        return analysis_result

    async def generate_decision(
        self, case_id: str
    ) -> Dict[str, Any]:
        """Generate decision recommendation for a case."""
        case = self._store.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        case.status = InvestigationStatus.DECISION_PENDING
        case.updated_at = datetime.now(timezone.utc)
        self._store.store_case(case)

        # Get evidence and assessment
        evidence = self._store.get_evidence_for_case(case_id)
        assessment = self._store.get_latest_assessment(case_id)

        # Generate decision
        decision = await self._decision.generate_decision(
            case=case,
            evidence=evidence,
            assessment=assessment,
        )

        # Store recommendation
        self._store.store_recommendation(case_id, decision)

        # Generate explanation
        explanation = await self._explainability.explain_decision(
            decision=decision,
            case=case,
            evidence=evidence,
        )

        self._log_operation("decision_generated", case_id, {
            "decision_type": decision.decision_type.value,
            "confidence": decision.confidence,
        })

        return {
            "decision": decision,
            "explanation": explanation,
        }

    async def complete_investigation(
        self,
        case_id: str,
        final_status: InvestigationStatus = InvestigationStatus.CLOSED,
    ) -> InvestigationCase:
        """Complete an investigation."""
        case = self._store.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        case.status = final_status
        case.completed_at = datetime.now(timezone.utc)
        case.updated_at = datetime.now(timezone.utc)

        self._store.store_case(case)

        self._log_operation("investigation_completed", case_id, {
            "final_status": final_status.value,
        })

        return case

    def escalate_investigation(
        self, case_id: str, reason: str
    ) -> InvestigationCase:
        """Escalate an investigation."""
        case = self._store.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        case.status = InvestigationStatus.ESCALATED
        case.priority = CasePriority.P0_CRITICAL
        case.updated_at = datetime.now(timezone.utc)
        case.metadata["escalation_reason"] = reason

        self._store.store_case(case)

        self._log_operation("investigation_escalated", case_id, {
            "reason": reason,
        })

        return case

    def get_investigation_summary(
        self, case_id: str
    ) -> Dict[str, Any]:
        """Get investigation summary."""
        case = self._store.get_case(case_id)
        if not case:
            return {"error": "Case not found"}

        evidence = self._store.get_evidence_for_case(case_id)
        recommendations = self._store.get_recommendations(case_id)
        latest_narrative = self._store.get_narrative_for_case(case_id)

        return {
            "case_id": case.case_id,
            "title": case.title,
            "status": case.status.value,
            "priority": case.priority.value,
            "severity": case.severity.value,
            "risk_score": case.risk_score,
            "confidence_score": case.confidence_score,
            "evidence_count": len(evidence),
            "findings_count": len(case.findings),
            "patterns_count": len(case.patterns_detected),
            "correlations_count": case.correlations_found,
            "latest_narrative": latest_narrative.summary if latest_narrative else None,
            "pending_recommendations": len(recommendations),
            "created_at": case.created_at.isoformat(),
            "updated_at": case.updated_at.isoformat(),
        }

    async def _perform_analysis(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> Dict[str, Any]:
        """Perform investigation analysis."""
        findings = []
        patterns = []
        total_risk = 0.0
        correlation_count = 0

        # Analyze each evidence item
        for artifact in evidence:
            # Check for risk indicators
            risk_indicators = self._analyze_evidence(artifact)
            findings.extend(risk_indicators["findings"])
            total_risk += artifact.relevance_score * risk_indicators["risk_score"]

            # Detect patterns
            if risk_indicators["pattern_match"]:
                patterns.extend(risk_indicators["pattern_match"])

            correlation_count += risk_indicators["correlations"]

        # Calculate final scores
        avg_risk = total_risk / len(evidence) if evidence else 0.5
        confidence = min(1.0, len(evidence) / 10) if evidence else 0.3

        return {
            "findings": findings[:20],  # Limit findings
            "patterns": list(set(patterns))[:10],  # Deduplicate patterns
            "risk_score": avg_risk,
            "confidence": confidence,
            "correlations_count": correlation_count,
        }

    def _analyze_evidence(
        self, evidence: EvidenceArtifact
    ) -> Dict[str, Any]:
        """Analyze individual evidence item."""
        findings = []
        patterns = []
        correlations = 0

        content = evidence.content
        evidence_type = evidence.evidence_type

        # Analyze based on evidence type
        if evidence_type == EvidenceType.TRANSACTION:
            if content.get("amount", 0) > 10000:
                findings.append("High-value transaction detected")
            if content.get("velocity", 0) > 5:
                findings.append("High velocity transaction pattern")

        elif evidence_type == EvidenceType.ACCOUNT:
            if content.get("age_days", 999) < 30:
                findings.append("New account with limited history")
            if content.get("kyc_status") == "pending":
                findings.append("KYC verification pending")

        elif evidence_type == EvidenceType.DEVICE:
            if content.get("is_new_device"):
                findings.append("First-time device usage")
            if content.get("risk_score", 0) > 0.7:
                findings.append("High-risk device detected")

        elif evidence_type == EvidenceType.IP_ADDRESS:
            if content.get("is_vpn") or content.get("is_proxy"):
                findings.append("Anonymous network detected")
            if content.get("country_risk") == "high":
                findings.append("High-risk country of origin")

        # Calculate risk score
        risk_score = evidence.relevance_score * 0.5
        if findings:
            risk_score += 0.3
        if patterns:
            risk_score += 0.2

        return {
            "findings": findings,
            "pattern_match": patterns,
            "risk_score": min(1.0, risk_score),
            "correlations": correlations,
        }

    def _calculate_severity(self, risk_score: float) -> SeverityLevel:
        """Calculate severity from risk score."""
        if risk_score >= 0.9:
            return SeverityLevel.CRITICAL
        elif risk_score >= 0.7:
            return SeverityLevel.SEVERE
        elif risk_score >= 0.5:
            return SeverityLevel.MODERATE
        elif risk_score >= 0.3:
            return SeverityLevel.WARNING
        else:
            return SeverityLevel.INFO

    def _log_operation(
        self, operation: str, case_id: str, details: Dict[str, Any]
    ) -> None:
        """Log operation for audit."""
        from .models import AuditRecord

        record = AuditRecord(
            record_id=str(uuid.uuid4()),
            operation=operation,
            case_id=case_id,
            user_id="system",
            action=operation,
            details=details,
        )
        self._store.store_audit_record(record)


# Global engine instance
_engine: Optional[InvestigationEngine] = None


def get_investigation_engine() -> InvestigationEngine:
    """Get the investigation engine instance."""
    global _engine
    if _engine is None:
        _engine = InvestigationEngine()
    return _engine