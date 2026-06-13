"""
Tests for Fraud Analyst Copilot.
"""

import asyncio
import pytest

from src.fraud_copilot import (
    CaseSummary,
    CopilotSession,
    InsightType,
    MessageRole,
    RecommendationType,
    ThreatExplanation,
    FraudCopilotStore,
    get_copilot_store,
    reset_copilot_store,
    CopilotEngine,
    SearchEngine,
    RecommendationEngine,
    FraudCopilotService,
)


class TestModels:
    """Test data models."""

    def test_copilot_session_creation(self):
        """Test copilot session creation."""
        session = CopilotSession(
            session_id="session-1",
            user_id="user-1",
            case_id="case-1",
        )
        assert session.session_id == "session-1"
        assert session.user_id == "user-1"
        assert session.active is True

    def test_case_summary_creation(self):
        """Test case summary creation."""
        summary = CaseSummary(
            summary_id="sum-1",
            case_id="case-1",
            summary_text="Test summary",
            key_findings=["Finding 1"],
            risk_factors=["Risk 1"],
        )
        assert summary.summary_id == "sum-1"
        assert len(summary.key_findings) == 1

    def test_threat_explanation_creation(self):
        """Test threat explanation creation."""
        explanation = ThreatExplanation(
            explanation_id="exp-1",
            case_id="case-1",
            topic="fraud",
            explanation_text="Fraud explanation",
        )
        assert explanation.explanation_id == "exp-1"


class TestStore:
    """Test copilot store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_copilot_store()
        self.store = get_copilot_store()

    def test_create_session(self):
        """Test creating a session."""
        session = self.store.create_session("session-1", "user-1")
        assert session is not None
        assert session.session_id == "session-1"

    def test_add_message(self):
        """Test adding a message."""
        self.store.create_session("session-1", "user-1")
        message = self.store.add_message(
            "session-1",
            MessageRole.USER,
            "Test message",
        )
        assert message is not None
        assert message.role == MessageRole.USER

    def test_search_knowledge(self):
        """Test knowledge search."""
        from src.fraud_copilot import KnowledgeDocument
        doc = KnowledgeDocument(
            document_id="doc-1",
            title="Fraud Detection",
            content="Fraud detection patterns",
            category="fraud",
            tags=["fraud", "detection"],
        )
        self.store.add_knowledge_document(doc)
        
        results = self.store.search_knowledge("fraud")
        assert len(results) >= 1


class TestCopilotEngine:
    """Test copilot engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_copilot_store()
        self.engine = CopilotEngine()

    def test_create_session(self):
        """Test creating a session."""
        result = asyncio.run(self.engine.create_session("user-1"))
        assert "session_id" in result
        assert result["status"] == "active"

    def test_chat(self):
        """Test chat functionality."""
        session_result = asyncio.run(self.engine.create_session("user-1"))
        session_id = session_result["session_id"]
        
        response = asyncio.run(self.engine.chat(session_id, "user-1", "Hello"))
        assert "content" in response
        assert len(response["content"]) > 0

    def test_analyze(self):
        """Test analysis functionality."""
        session_result = asyncio.run(self.engine.create_session("user-1"))
        session_id = session_result["session_id"]
        
        result = asyncio.run(self.engine.analyze(session_id, "case-1", "pattern"))
        assert "insights" in result
        assert len(result["insights"]) >= 1

    def test_summarize(self):
        """Test summarization."""
        session_result = asyncio.run(self.engine.create_session("user-1"))
        session_id = session_result["session_id"]
        
        result = asyncio.run(self.engine.summarize(
            session_id,
            "case-1",
            {"title": "Test Case", "risk_score": 0.8},
        ))
        assert "summary_id" in result
        assert "summary_text" in result

    def test_recommend(self):
        """Test recommendations."""
        session_result = asyncio.run(self.engine.create_session("user-1"))
        session_id = session_result["session_id"]
        
        recommendations = asyncio.run(self.engine.recommend(session_id, "case-1"))
        assert isinstance(recommendations, list)
        assert len(recommendations) >= 1

    def test_explain(self):
        """Test threat explanation."""
        session_result = asyncio.run(self.engine.create_session("user-1"))
        session_id = session_result["session_id"]
        
        result = asyncio.run(self.engine.explain(session_id, "case-1", "fraud"))
        assert "explanation" in result

    def test_report(self):
        """Test report generation."""
        session_result = asyncio.run(self.engine.create_session("user-1"))
        session_id = session_result["session_id"]
        
        result = asyncio.run(self.engine.report(session_id, "case-1"))
        assert "report_id" in result
        assert "sections" in result

    def test_get_history(self):
        """Test getting conversation history."""
        session_result = asyncio.run(self.engine.create_session("user-1"))
        session_id = session_result["session_id"]
        
        asyncio.run(self.engine.chat(session_id, "user-1", "Hello"))
        
        history = self.engine.get_history(session_id)
        assert len(history) >= 2


class TestSearchEngine:
    """Test search engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_copilot_store()
        self.search = SearchEngine()

    def test_search(self):
        """Test knowledge search."""
        results = asyncio.run(self.search.search("fraud"))
        assert isinstance(results, list)
        assert len(results) >= 1

    def test_add_document(self):
        """Test adding a document."""
        result = asyncio.run(self.search.add_document(
            title="Test Document",
            content="Test content about fraud detection",
            category="test",
            tags=["test", "fraud"],
        ))
        assert result["status"] == "added"

    def test_semantic_search(self):
        """Test semantic search."""
        result = asyncio.run(self.search.semantic_search(
            "fraud detection",
            case_context={"category": "fraud"},
        ))
        assert "results" in result
        assert result["total_results"] >= 1


class TestRecommendationEngine:
    """Test recommendation engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_copilot_store()
        self.engine = RecommendationEngine()

    def test_generate_recommendations(self):
        """Test generating recommendations."""
        recommendations = asyncio.run(self.engine.generate_recommendations(
            "case-1",
            {"risk_score": 0.8, "linked_entities": 5},
        ))
        assert len(recommendations) >= 3

    def test_get_prioritized_recommendations(self):
        """Test getting prioritized recommendations."""
        asyncio.run(self.engine.generate_recommendations(
            "case-1",
            {"risk_score": 0.6},
        ))
        
        prioritized = asyncio.run(self.engine.get_prioritized_recommendations("case-1"))
        assert len(prioritized) >= 1


class TestFraudCopilotService:
    """Test main service."""

    def setup_method(self):
        """Reset store before each test."""
        reset_copilot_store()
        self.service = FraudCopilotService()

    def test_chat_new_session(self):
        """Test chat with new session."""
        result = asyncio.run(self.service.chat(
            user_id="user-1",
            message="Hello",
        ))
        assert "content" in result

    def test_chat_existing_session(self):
        """Test chat with existing session."""
        session_result = asyncio.run(self.service.chat(
            user_id="user-1",
            message="Hello",
        ))
        session_id = session_result.get("session_id")
        
        result = asyncio.run(self.service.chat(
            user_id="user-1",
            message="Help me",
            session_id=session_id,
        ))
        assert "content" in result

    def test_search_knowledge(self):
        """Test knowledge search."""
        results = asyncio.run(self.service.search_knowledge("fraud"))
        assert isinstance(results, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])