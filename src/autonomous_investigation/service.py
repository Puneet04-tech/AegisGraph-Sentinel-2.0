"""
Main Service for Autonomous Fraud Investigation & Decision Intelligence Platform.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    CasePriority,
    EvidenceType,
    AuditRecord,
)
from .store import InvestigationStore, get_investigation_store
from .investigation_engine import get_investigation_engine
from .evidence_collector import get_evidence_collector
from .decision_engine import get_decision_engine
from .case_prioritization import get_case_prioritization_engine
from .report_generator import get_report_generator
from .recommendation_engine import get_recommendation_engine
from .explainability import get_explainability_engine


class InvestigationConfig:
    """Configuration for investigation service."""
    default_priority: CasePriority = CasePriority.P2_MEDIUM
    auto_escalate_threshold: float = 0.9
    evidence_collection_timeout: int = 300
    analysis_timeout: int = 600
    sla_hours: int = 24


class InvestigationService:
    """
    Main orchestrator for autonomous fraud investigation.

    Integrates all components:
    - Investigation Engine
    - Evidence Collector
    - Decision Intelligence
    - Case Prioritization
    - Report Generation
    - Recommendation Engine
    - Explainability
    """

    def __init__(
        self,
        store: Optional[InvestigationStore] = None,
        config: Optional[InvestigationConfig] = None,
    ):
        self._store = store or get_investigation_store()
        self._config = config or InvestigationConfig()

        # Initialize engines
        self._investigation = get_investigation_engine()
        self._evidence = get_evidence_collector()
        self._decision = get_decision_engine()
        self._prioritization = get_case_prioritization_engine()
        self._report = get_report_generator()
        self._recommendation = get_recommendation_engine()
        self._explainability = get_explainability_engine()

    # Investigation CRUD
    async def create_investigation(
        self,
        title: str,
        description: str,
        alert_ids: Optional[List[str]] = None,
        entity_ids: Optional[List[str]] = None,
        priority: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new investigation."""
        case = self._investigation.create_investigation(
            title=title,
            description=description,
            alert_ids=alert_ids,
            entity_ids=entity_ids,
            priority=CasePriority(priority) if priority else CasePriority.P2_MEDIUM,
        )

        # Set SLA deadline
        case.sla_deadline = datetime.now(timezone.utc) + timedelta(
            hours=self._config.sla_hours
        )
        self._store.store_case(case)

        self._log_operation("investigation_create", case.case_id, {"title": title})

        return {
            "case_id": case.case_id,
            "title": case.title,
            "status": case.status.value,
            "priority": case.priority.value,
        }

    async def get_investigation(self, case_id: str) -> Dict[str, Any]:
        """Get investigation details."""
        case = self._store.get_case(case_id)
        if not case:
            return {"error": "Investigation not found"}

        return self._investigation.get_investigation_summary(case_id)

    async def list_investigations(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List investigations."""
        if status:
            cases = self._store.get_cases_by_status(status, limit)
        elif priority:
            cases = self._store.get_cases_by_priority(priority, limit)
        else:
            cases = self._store.get_all_cases(limit)

        return [
            {
                "case_id": c.case_id,
                "title": c.title,
                "status": c.status.value,
                "priority": c.priority.value,
                "risk_score": c.risk_score,
                "created_at": c.created_at.isoformat(),
            }
            for c in cases
        ]

    # Investigation Workflow
    async def start_investigation(self, case_id: str) -> Dict[str, Any]:
        """Start an investigation."""
        case = await self._investigation.start_investigation(case_id)

        self._log_operation("investigation_start", case_id, {})

        return {"case_id": case.case_id, "status": case.status.value}

    async def run_full_investigation(self, case_id: str) -> Dict[str, Any]:
        """Run complete investigation workflow."""
        case = self._store.get_case(case_id)
        if not case:
            return {"error": "Investigation not found"}

        # Step 1: Start
        await self._investigation.start_investigation(case_id)

        # Step 2: Collect Evidence
        evidence = await self._investigation.collect_evidence(case_id)

        # Step 3: Analyze
        analysis = await self._investigation.analyze_investigation(case_id)

        # Step 4: Generate Decision
        decision_result = await self._investigation.generate_decision(case_id)

        # Auto-escalate if needed
        if analysis["risk_score"] >= self._config.auto_escalate_threshold:
            self._investigation.escalate_investigation(
                case_id,
                f"Auto-escalated: risk score {analysis['risk_score']:.2f} exceeds threshold"
            )

        self._log_operation("full_investigation_completed", case_id, {
            "evidence_count": len(evidence),
            "findings_count": len(analysis["findings"]),
            "risk_score": analysis["risk_score"],
        })

        return {
            "case_id": case_id,
            "status": "completed",
            "evidence_collected": len(evidence),
            "analysis": analysis,
            "decision": {
                "type": decision_result["decision"].decision_type.value,
                "confidence": decision_result["decision"].confidence,
            },
        }

    # Evidence
    async def collect_evidence(
        self,
        case_id: str,
        evidence_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Collect evidence for a case."""
        types = [EvidenceType(t) for t in (evidence_types or [])]
        evidence = await self._investigation.collect_evidence(case_id, types)

        return [
            {
                "evidence_id": e.evidence_id,
                "type": e.evidence_type.value,
                "source": e.source_system,
                "relevance": e.relevance_score,
                "collected_at": e.collected_at.isoformat(),
            }
            for e in evidence
        ]

    async def get_evidence(self, case_id: str) -> List[Dict[str, Any]]:
        """Get evidence for a case."""
        evidence = self._store.get_evidence_for_case(case_id)

        return [
            {
                "evidence_id": e.evidence_id,
                "type": e.evidence_type.value,
                "source": e.source_system,
                "content": e.content,
                "relevance": e.relevance_score,
                "is_verified": e.is_verified,
            }
            for e in evidence
        ]

    # Analysis & Decision
    async def analyze_investigation(self, case_id: str) -> Dict[str, Any]:
        """Analyze an investigation."""
        return await self._investigation.analyze_investigation(case_id)

    async def get_decision(self, case_id: str) -> Dict[str, Any]:
        """Get decision recommendation for a case."""
        recommendations = self._store.get_recommendations(case_id)
        if not recommendations:
            return {"error": "No decision available"}

        latest = recommendations[-1]
        return {
            "decision_type": latest.decision_type.value,
            "confidence": latest.confidence,
            "risk_explanation": latest.risk_explanation,
            "recommended_actions": latest.recommended_actions,
            "requires_human_review": latest.requires_human_review,
        }

    # Reports
    async def generate_report(self, case_id: str) -> Dict[str, Any]:
        """Generate investigation report."""
        case = self._store.get_case(case_id)
        if not case:
            return {"error": "Investigation not found"}

        evidence = self._store.get_evidence_for_case(case_id)

        # Generate narrative
        narrative = await self._report.generate_narrative(
            case=case,
            evidence=evidence,
            findings=case.findings,
        )

        # Store narrative
        self._store.store_narrative(narrative)

        # Generate timeline
        timeline = await self._report.generate_timeline(case, evidence)

        return {
            "case_id": case_id,
            "narrative": {
                "summary": narrative.summary,
                "detailed": narrative.detailed_narrative,
                "key_findings": narrative.key_findings,
                "fraud_indicators": narrative.fraud_indicators,
                "financial_impact": narrative.financial_impact,
            },
            "timeline": {
                "events": timeline.events,
                "critical_path": timeline.critical_path,
                "anomalies": timeline.anomalies_detected,
            },
        }

    async def get_executive_summary(self, case_id: str) -> str:
        """Get executive summary for a case."""
        case = self._store.get_case(case_id)
        if not case:
            return "Investigation not found"

        narrative = self._store.get_narrative_for_case(case_id)
        if not narrative:
            return "Report not yet generated"

        return await self._report.generate_executive_summary(case, narrative)

    # Recommendations
    async def get_analyst_recommendations(
        self, case_id: str
    ) -> List[Dict[str, Any]]:
        """Get recommendations for analysts."""
        case = self._store.get_case(case_id)
        if not case:
            return []

        evidence = self._store.get_evidence_for_case(case_id)
        recommendations = await self._recommendation.generate_analyst_recommendations(
            case, evidence
        )

        return [
            {
                "recommendation_id": r.recommendation_id,
                "type": r.recommendation_type,
                "description": r.description,
                "priority": r.priority.value,
                "actions": r.suggested_actions,
                "questions": r.questions_to_answer,
            }
            for r in recommendations
        ]

    # Dashboard
    async def get_dashboard(self) -> Dict[str, Any]:
        """Get investigation dashboard."""
        stats = self._store.get_stats()
        open_cases = self._store.get_open_cases(limit=100)

        # Calculate queue metrics
        queue_metrics = self._prioritization.get_queue_metrics(open_cases)

        # Get high-priority cases
        critical = self._store.get_cases_by_priority(
            CasePriority.P0_CRITICAL.value, limit=10
        )

        return {
            "total_cases": stats["total_cases"],
            "open_cases": stats["open_cases"],
            "high_priority_cases": stats["high_priority_cases"],
            "queue_metrics": queue_metrics,
            "critical_cases": [
                {"case_id": c.case_id, "title": c.title, "risk_score": c.risk_score}
                for c in critical
            ],
        }

    # Prioritization
    async def get_next_case(
        self, analyst_workload: Optional[Dict[str, int]] = None
    ) -> Optional[Dict[str, Any]]:
        """Get next case to work on."""
        open_cases = self._store.get_open_cases(limit=1000)
        next_case = self._prioritization.get_next_case(open_cases, analyst_workload)

        if not next_case:
            return None

        return {
            "case_id": next_case.case_id,
            "title": next_case.title,
            "priority": next_case.priority.value,
            "risk_score": next_case.risk_score,
            "sla_status": self._prioritization.get_sla_status(next_case),
        }

    # Explainability
    async def explain_decision(self, case_id: str) -> Dict[str, Any]:
        """Get decision explanation."""
        recommendations = self._store.get_recommendations(case_id)
        if not recommendations:
            return {"error": "No decision available"}

        case = self._store.get_case(case_id)
        evidence = self._store.get_evidence_for_case(case_id)
        decision = recommendations[-1]

        return await self._explainability.explain_decision(decision, case, evidence)

    def _log_operation(
        self, operation: str, case_id: str, details: Dict[str, Any]
    ) -> None:
        """Log operation for audit."""
        record = AuditRecord(
            record_id=str(uuid.uuid4()),
            operation=operation,
            case_id=case_id,
            user_id="system",
            action=operation,
            details=details,
        )
        self._store.store_audit_record(record)


# Global service instance
_service: Optional[InvestigationService] = None


def get_investigation_service() -> InvestigationService:
    """Get the investigation service instance."""
    global _service
    if _service is None:
        _service = InvestigationService()
    return _service