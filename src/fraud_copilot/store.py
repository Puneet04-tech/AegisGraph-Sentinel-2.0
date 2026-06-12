"""
Fraud Copilot Store.

Storage layer for copilot sessions and data.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    AuditEvent,
    CaseSummary,
    CopilotSession,
    GeneratedReport,
    InsightType,
    InvestigationInsight,
    KnowledgeDocument,
    MessageRole,
    Recommendation,
    RecommendationType,
    ThreatExplanation,
    ConversationMessage,
)


class FraudCopilotStore:
    """Store for fraud copilot data."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._sessions: Dict[str, CopilotSession] = {}
        self._summaries: Dict[str, CaseSummary] = {}
        self._explanations: Dict[str, ThreatExplanation] = {}
        self._recommendations: Dict[str, List[Recommendation]] = {}
        self._insights: Dict[str, List[InvestigationInsight]] = {}
        self._knowledge: Dict[str, KnowledgeDocument] = {}
        self._reports: Dict[str, GeneratedReport] = {}
        self._audit_log: List[AuditEvent] = []
        self._lock = threading.RLock()

    def create_session(
        self,
        session_id: str,
        user_id: str,
        case_id: Optional[str] = None,
    ) -> CopilotSession:
        """Create a new copilot session."""
        session = CopilotSession(
            session_id=session_id,
            user_id=user_id,
            case_id=case_id,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[CopilotSession]:
        """Get a session by ID."""
        return self._sessions.get(session_id)

    def add_message(
        self,
        session_id: str,
        role: MessageRole,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[ConversationMessage]:
        """Add a message to a session."""
        session = self._sessions.get(session_id)
        if not session:
            return None
        
        message = ConversationMessage(
            message_id=f"msg-{len(session.messages) + 1}",
            role=role,
            content=content,
            metadata=metadata or {},
        )
        
        with self._lock:
            session.messages.append(message)
            session.updated_at = datetime.now(timezone.utc)
        
        return message

    def get_session_history(self, session_id: str) -> List[ConversationMessage]:
        """Get message history for a session."""
        session = self._sessions.get(session_id)
        if not session:
            return []
        return session.messages

    def store_summary(self, summary: CaseSummary) -> None:
        """Store a case summary."""
        with self._lock:
            self._summaries[summary.case_id] = summary

    def get_summary(self, case_id: str) -> Optional[CaseSummary]:
        """Get summary for a case."""
        return self._summaries.get(case_id)

    def store_explanation(self, explanation: ThreatExplanation) -> None:
        """Store a threat explanation."""
        with self._lock:
            self._explanations[explanation.explanation_id] = explanation

    def get_explanation(self, explanation_id: str) -> Optional[ThreatExplanation]:
        """Get an explanation by ID."""
        return self._explanations.get(explanation_id)

    def store_recommendation(self, case_id: str, recommendation: Recommendation) -> None:
        """Store a recommendation for a case."""
        with self._lock:
            if case_id not in self._recommendations:
                self._recommendations[case_id] = []
            self._recommendations[case_id].append(recommendation)

    def get_recommendations(self, case_id: str) -> List[Recommendation]:
        """Get recommendations for a case."""
        return self._recommendations.get(case_id, [])

    def store_insight(self, case_id: str, insight: InvestigationInsight) -> None:
        """Store an investigation insight."""
        with self._lock:
            if case_id not in self._insights:
                self._insights[case_id] = []
            self._insights[case_id].append(insight)

    def get_insights(self, case_id: str) -> List[InvestigationInsight]:
        """Get insights for a case."""
        return self._insights.get(case_id, [])

    def add_knowledge_document(self, document: KnowledgeDocument) -> None:
        """Add a knowledge document."""
        with self._lock:
            self._knowledge[document.document_id] = document

    def search_knowledge(self, query: str, limit: int = 10) -> List[KnowledgeDocument]:
        """Search knowledge base."""
        query_lower = query.lower()
        results = []
        
        for doc in self._knowledge.values():
            if query_lower in doc.title.lower():
                results.append(doc)
            elif query_lower in doc.content.lower():
                results.append(doc)
            elif any(query_lower in tag.lower() for tag in doc.tags):
                results.append(doc)
        
        return results[:limit]

    def store_report(self, report: GeneratedReport) -> None:
        """Store a generated report."""
        with self._lock:
            self._reports[report.report_id] = report

    def get_report(self, report_id: str) -> Optional[GeneratedReport]:
        """Get a report by ID."""
        return self._reports.get(report_id)

    def log_audit(
        self,
        user_id: str,
        action: str,
        session_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """Log an audit event."""
        event = AuditEvent(
            event_id=f"audit-{len(self._audit_log) + 1}",
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            action=action,
            session_id=session_id,
            details=details or {},
            success=success,
        )
        with self._lock:
            self._audit_log.append(event)

    def get_audit_log(self, limit: int = 100) -> List[AuditEvent]:
        """Get audit log entries."""
        return self._audit_log[-limit:]

    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._sessions.clear()
            self._summaries.clear()
            self._explanations.clear()
            self._recommendations.clear()
            self._insights.clear()
            self._knowledge.clear()
            self._reports.clear()
            self._audit_log.clear()


# Singleton instance
_store: Optional[FraudCopilotStore] = None
_store_lock = threading.Lock()


def get_copilot_store() -> FraudCopilotStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = FraudCopilotStore()
    return _store


def reset_copilot_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None