"""
Fraud Copilot Service.

Main service for the fraud analyst copilot.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import AuditEvent, CopilotSession
from .store import (
    FraudCopilotStore,
    get_copilot_store,
    reset_copilot_store,
)
from .copilot_engine import (
    CopilotEngine,
    get_copilot_engine,
    reset_copilot_engine,
)
from .search_engine import (
    SearchEngine,
    get_search_engine,
    reset_search_engine,
)
from .recommendation_engine import (
    RecommendationEngine,
    get_recommendation_engine,
    reset_recommendation_engine,
)


class FraudCopilotService:
    """Main service for fraud analyst copilot."""

    def __init__(self, store: Optional[FraudCopilotStore] = None) -> None:
        """Initialize the service."""
        self.store = store or get_copilot_store()
        self.engine = get_copilot_engine()
        self.search = get_search_engine()
        self.recommendations = get_recommendation_engine()

    async def chat(
        self,
        user_id: str,
        message: str,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Process a chat message."""
        if session_id:
            return await self.engine.chat(session_id, user_id, message)
        
        session_result = await self.engine.create_session(user_id=user_id)
        new_session_id = session_result["session_id"]
        
        return await self.engine.chat(new_session_id, user_id, message)

    async def analyze(
        self,
        session_id: str,
        case_id: str,
        analysis_type: str,
    ) -> Dict[str, Any]:
        """Perform analysis on a case."""
        return await self.engine.analyze(session_id, case_id, analysis_type)

    async def summarize(
        self,
        session_id: str,
        case_id: str,
        case_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate case summary."""
        return await self.engine.summarize(session_id, case_id, case_data)

    async def recommend(
        self,
        session_id: str,
        case_id: str,
    ) -> List[Dict[str, Any]]:
        """Generate recommendations."""
        return await self.engine.recommend(session_id, case_id)

    async def explain(
        self,
        session_id: str,
        case_id: str,
        topic: str,
    ) -> Dict[str, Any]:
        """Explain a threat."""
        return await self.engine.explain(session_id, case_id, topic)

    async def report(
        self,
        session_id: str,
        case_id: str,
        report_type: str = "standard",
    ) -> Dict[str, Any]:
        """Generate investigation report."""
        return await self.engine.report(session_id, case_id, report_type)

    async def search_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search the knowledge base."""
        return await self.search.search(query, category)

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session details."""
        return self.engine.get_session(session_id)

    async def get_history(self, session_id: str) -> List[Dict[str, Any]]:
        """Get conversation history."""
        return self.engine.get_history(session_id)

    async def get_insights(self, case_id: str) -> List[Dict[str, Any]]:
        """Get insights for a case."""
        insights = self.store.get_insights(case_id)
        return [
            {
                "id": i.insight_id,
                "type": i.insight_type.value,
                "title": i.title,
                "description": i.description,
                "confidence": i.confidence,
            }
            for i in insights
        ]

    async def get_audit(
        self,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit log."""
        events = self.store.get_audit_log(limit)
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "user_id": e.user_id,
                "action": e.action,
                "session_id": e.session_id,
                "success": e.success,
            }
            for e in events
        ]


# Singleton instance
_service: Optional[FraudCopilotService] = None


def get_fraud_copilot_service() -> FraudCopilotService:
    """Get the global service instance."""
    global _service
    if _service is None:
        _service = FraudCopilotService()
    return _service


def reset_fraud_copilot_service() -> None:
    """Reset the global service."""
    global _service
    _service = None
    reset_copilot_store()
    reset_copilot_engine()
    reset_search_engine()
    reset_recommendation_engine()