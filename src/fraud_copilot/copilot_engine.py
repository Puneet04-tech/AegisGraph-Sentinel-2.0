"""
Copilot Engine.

Core engine for the fraud analyst copilot.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    CaseSummary,
    CopilotSession,
    DecisionSupport,
    GeneratedReport,
    InsightType,
    InvestigationInsight,
    KnowledgeDocument,
    MessageRole,
    ReportSection,
    ThreatExplanation,
    ConversationMessage,
)
from .store import FraudCopilotStore, get_copilot_store
from .recommendation_engine import get_recommendation_engine


class CopilotEngine:
    """Core engine for fraud analyst copilot."""

    def __init__(self, store: Optional[FraudCopilotStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_copilot_store()
        self.recommendations = get_recommendation_engine()

    async def create_session(
        self,
        user_id: str,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new copilot session."""
        session_id = f"session-{uuid.uuid4().hex[:12]}"
        
        session = self.store.create_session(
            session_id=session_id,
            user_id=user_id,
            case_id=case_id,
        )
        
        self.store.log_audit(
            user_id=user_id,
            action="session_created",
            session_id=session_id,
            details={"case_id": case_id},
        )
        
        return {
            "session_id": session_id,
            "status": "active",
            "created_at": session.created_at.isoformat(),
        }

    async def chat(
        self,
        session_id: str,
        user_id: str,
        message: str,
    ) -> Dict[str, Any]:
        """Process a chat message."""
        session = self.store.get_session(session_id)
        if not session:
            return {"error": "Session not found"}
        
        self.store.add_message(
            session_id=session_id,
            role=MessageRole.USER,
            content=message,
        )
        
        response = self._generate_response(message, session)
        
        self.store.add_message(
            session_id=session_id,
            role=MessageRole.ASSISTANT,
            content=response["content"],
            metadata={"intent": response.get("intent")},
        )
        
        self.store.log_audit(
            user_id=user_id,
            action="chat_message",
            session_id=session_id,
        )
        
        return {
            "message_id": f"msg-{len(session.messages)}",
            "content": response["content"],
            "intent": response.get("intent"),
        }

    def _generate_response(self, message: str, session: CopilotSession) -> Dict[str, Any]:
        """Generate a response to user message."""
        message_lower = message.lower()
        
        if any(word in message_lower for word in ["help", "what", "how", "explain"]):
            return {
                "content": "I can help you with fraud analysis, case investigation, threat explanation, report generation, and recommendations. What would you like assistance with?",
                "intent": "general_assistance",
            }
        
        if "summarize" in message_lower:
            return {
                "content": "I can generate a case summary based on the investigation data. Please provide the case_id for summarization.",
                "intent": "summarization_request",
            }
        
        if "recommend" in message_lower or "suggest" in message_lower:
            return {
                "content": "Based on the case context, I recommend reviewing transaction patterns and identifying anomalies. Would you like me to generate specific recommendations?",
                "intent": "recommendation_request",
            }
        
        return {
            "content": "I'm here to help with your fraud investigation. I can analyze patterns, explain threats, generate reports, and provide recommendations based on the available data.",
            "intent": "general_response",
        }

    async def analyze(
        self,
        session_id: str,
        case_id: str,
        analysis_type: str,
    ) -> Dict[str, Any]:
        """Perform analysis on a case."""
        session = self.store.get_session(session_id)
        if not session:
            return {"error": "Session not found"}
        
        session.context["case_id"] = case_id
        session.context["last_analysis"] = {
            "type": analysis_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        insights = self._perform_analysis(analysis_type, case_id)
        
        for insight in insights:
            self.store.store_insight(case_id, insight)
        
        return {
            "case_id": case_id,
            "analysis_type": analysis_type,
            "insights": [
                {"id": i.insight_id, "type": i.insight_type.value, "title": i.title}
                for i in insights
            ],
        }

    def _perform_analysis(self, analysis_type: str, case_id: str) -> List[InvestigationInsight]:
        """Perform analysis and return insights."""
        insights = []
        
        if analysis_type in ["pattern", "all"]:
            insights.append(InvestigationInsight(
                insight_id=str(uuid.uuid4()),
                case_id=case_id,
                insight_type=InsightType.PATTERN,
                title="Transaction Pattern Detected",
                description="Identified unusual transaction patterns requiring review",
                confidence=0.85,
            ))
        
        if analysis_type in ["anomaly", "all"]:
            insights.append(InvestigationInsight(
                insight_id=str(uuid.uuid4()),
                case_id=case_id,
                insight_type=InsightType.ANOMALY,
                title="Anomaly Detected",
                description="Found statistical anomaly in transaction behavior",
                confidence=0.78,
            ))
        
        if analysis_type in ["correlation", "all"]:
            insights.append(InvestigationInsight(
                insight_id=str(uuid.uuid4()),
                case_id=case_id,
                insight_type=InsightType.CORRELATION,
                title="Correlation Found",
                description="Linked to other suspicious activities in the network",
                confidence=0.82,
            ))
        
        return insights

    async def summarize(
        self,
        session_id: str,
        case_id: str,
        case_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate case summary."""
        summary_text = f"Investigation Summary for Case {case_id}: "
        
        if "title" in case_data:
            summary_text += f"Subject: {case_data['title']}. "
        
        if "risk_score" in case_data:
            summary_text += f"Risk Score: {case_data['risk_score']}. "
        
        key_findings = self._derive_findings(case_data)
        summary_text += " ".join(key_findings)
        
        summary = CaseSummary(
            summary_id=str(uuid.uuid4()),
            case_id=case_id,
            summary_text=summary_text,
            key_findings=key_findings,
            risk_factors=self._derive_risk_factors(case_data),
            recommended_actions=["Review transaction history", "Verify account ownership"],
        )
        
        self.store.store_summary(summary)
        
        return {
            "summary_id": summary.summary_id,
            "summary_text": summary.summary_text,
            "key_findings": summary.key_findings,
        }
    
    def _derive_findings(self, case_data: Dict[str, Any]) -> List[str]:
        """Derive key findings from case data."""
        findings = []
        if case_data.get("linked_entities", 0) > 3:
            findings.append(f"Case linked to {case_data['linked_entities']} other entities")
        if case_data.get("risk_score", 0.5) > 0.7:
            findings.append("Automated risk assessment flagged this case as high risk")
        if not findings:
            findings.append("No significant anomalies flagged by automated checks")
        return findings
    
    def _derive_risk_factors(self, case_data: Dict[str, Any]) -> List[str]:
        """Derive risk factors from case data."""
        factors = []
        if case_data.get("risk_score", 0.5) > 0.7:
            factors.append("Risk score above high-risk threshold")
        if case_data.get("linked_entities", 0) > 3:
            factors.append("Multiple linked entities suggest coordinated activity")
        if not factors:
            factors.append("Risk score within normal range")
        return factors

    async def recommend(
        self,
        session_id: str,
        case_id: str,
        case_data: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Generate recommendations for a case."""
        recommendations = await self.recommendations.generate_recommendations(
            case_id, case_data or {}
        )
        
        return [
            {
                "id": r.recommendation_id,
                "type": r.recommendation_type.value,
                "title": r.title,
                "priority": r.priority,
                "confidence": r.confidence,
            }
            for r in recommendations
        ]

    async def explain(
        self,
        session_id: str,
        case_id: str,
        topic: str,
    ) -> Dict[str, Any]:
        """Explain a threat or concept."""
        explanation_text = f"Threat Explanation for '{topic}' in Case {case_id}: "
        
        if "fraud" in topic.lower():
            explanation_text += "This involves unauthorized access or manipulation of financial transactions for personal gain. The typical attack chain includes: reconnaissance, initial access, lateral movement, and exfiltration."
        elif "mule" in topic.lower():
            explanation_text += "A mule account is used to transfer illegally obtained funds. Warning signs include: rapid account activation followed by high-volume transactions, mismatched geographic locations, and structured transactions."
        else:
            explanation_text += "This threat pattern involves suspicious activity that should be investigated further. Key indicators include unusual transaction patterns, geographic anomalies, and behavioral deviations."
        
        explanation = ThreatExplanation(
            explanation_id=str(uuid.uuid4()),
            case_id=case_id,
            topic=topic,
            explanation_text=explanation_text,
            attack_chain=[
                {"step": 1, "description": "Initial detection"},
                {"step": 2, "description": "Pattern analysis"},
                {"step": 3, "description": "Risk assessment"},
            ],
            confidence=0.85,
        )
        
        self.store.store_explanation(explanation)
        
        return {
            "explanation_id": explanation.explanation_id,
            "topic": topic,
            "explanation": explanation.explanation_text,
        }

    async def report(
        self,
        session_id: str,
        case_id: str,
        report_type: str = "standard",
        case_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate investigation report."""
        case_data = case_data or {}
        findings = self._derive_findings(case_data)
        recommendations = await self.recommendations.generate_recommendations(case_id, case_data)
        rec_titles = [r.title for r in recommendations]
        recommendations_text = (
            "Recommended actions: " + "; ".join(rec_titles)
            if rec_titles else "No specific actions recommended."
        )
        
        sections = [
            ReportSection(
                section_id=str(uuid.uuid4()),
                title="Executive Summary",
                content="This report summarizes the fraud investigation findings and recommendations.",
            ),
            ReportSection(
                section_id=str(uuid.uuid4()),
                title="Case Overview",
                content=f"Case ID: {case_id}. Investigation status: In Progress.",
            ),
            ReportSection(
                section_id=str(uuid.uuid4()),
                title="Findings",
                content=" ".join(findings),
            ),
            ReportSection(
                section_id=str(uuid.uuid4()),
                title="Recommendations",
                content=recommendations_text,
            ),
        ]
        
        report = GeneratedReport(
            report_id=str(uuid.uuid4()),
            case_id=case_id,
            title=f"Investigation Report - Case {case_id}",
            sections=sections,
            executive_summary="Fraud investigation completed with recommended actions.",
            recommendations=rec_titles,
        )
        
        self.store.store_report(report)
        
        return {
            "report_id": report.report_id,
            "title": report.title,
            "sections": [{"title": s.title} for s in sections],
        }

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session details."""
        session = self.store.get_session(session_id)
        if not session:
            return None
        
        return {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "case_id": session.case_id,
            "message_count": len(session.messages),
            "active": session.active,
            "created_at": session.created_at.isoformat(),
        }

    def get_history(self, session_id: str) -> List[Dict[str, Any]]:
        """Get conversation history."""
        messages = self.store.get_session_history(session_id)
        return [
            {
                "message_id": m.message_id,
                "role": m.role.value,
                "content": m.content,
                "timestamp": m.timestamp.isoformat(),
            }
            for m in messages
        ]


# Singleton instance
_engine: Optional[CopilotEngine] = None


def get_copilot_engine() -> CopilotEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = CopilotEngine()
    return _engine


def reset_copilot_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None