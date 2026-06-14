"""
Knowledge Search Engine.

Search engine for fraud investigation knowledge.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from .models import KnowledgeDocument
from .store import FraudCopilotStore, get_copilot_store


class SearchEngine:
    """Search engine for knowledge retrieval."""

    def __init__(self, store: Optional[FraudCopilotStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_copilot_store()
        self._initialize_default_knowledge()

    def _initialize_default_knowledge(self) -> None:
        """Initialize default knowledge base."""
        default_docs = [
            KnowledgeDocument(
                document_id="kb-001",
                title="Fraud Detection Patterns",
                content="Common fraud patterns include: synthetic identity fraud, account takeover, payment fraud, and merchant fraud. Detection involves analyzing transaction velocity, geographic anomalies, and behavioral patterns.",
                category="fraud_patterns",
                tags=["fraud", "detection", "patterns", "analysis"],
            ),
            KnowledgeDocument(
                document_id="kb-002",
                title="AML Typologies",
                content="Anti-Money Laundering typologies include: structuring, smurfing, round-tripping, layering, and integration. Each type has specific indicators and detection methods.",
                category="aml",
                tags=["aml", "money laundering", "typologies", "compliance"],
            ),
            KnowledgeDocument(
                document_id="kb-003",
                title="Investigation Best Practices",
                content="Effective fraud investigation involves: timeline analysis, entity relationship mapping, transaction pattern examination, and cross-referencing external data sources.",
                category="investigation",
                tags=["investigation", "best practices", "analysis", "methodology"],
            ),
        ]
        
        for doc in default_docs:
            if doc.document_id not in self.store._knowledge:
                self.store.add_knowledge_document(doc)

    async def search(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Search the knowledge base."""
        results = self.store.search_knowledge(query, limit=limit)
        
        if category:
            results = [r for r in results if r.category == category]
        
        return [
            {
                "document_id": d.document_id,
                "title": d.title,
                "category": d.category,
                "snippet": d.content[:200] + "..." if len(d.content) > 200 else d.content,
                "tags": d.tags,
                "relevance_score": self._calculate_relevance(d, query),
            }
            for d in results
        ]

    def _calculate_relevance(self, doc: KnowledgeDocument, query: str) -> float:
        """Calculate relevance score for a document."""
        score = 0.0
        query_lower = query.lower()
        
        if query_lower in doc.title.lower():
            score += 0.5
        if query_lower in doc.content.lower():
            score += 0.3
        if any(query_lower in tag.lower() for tag in doc.tags):
            score += 0.2
        
        return min(1.0, score)

    async def add_document(
        self,
        title: str,
        content: str,
        category: str,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add a document to the knowledge base."""
        document = KnowledgeDocument(
            document_id=f"kb-{uuid.uuid4().hex[:8]}",
            title=title,
            content=content,
            category=category,
            tags=tags or [],
        )
        
        self.store.add_knowledge_document(document)
        
        return {
            "document_id": document.document_id,
            "title": document.title,
            "status": "added",
        }

    async def semantic_search(
        self,
        query: str,
        case_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Perform semantic search with case context."""
        results = await self.search(query, limit=5)
        
        if case_context:
            for result in results:
                context_score = self._calculate_context_relevance(result, case_context)
                result["context_score"] = context_score
                result["combined_score"] = (
                    result.get("relevance_score", 0) * 0.7 +
                    context_score * 0.3
                )
        
        return {
            "query": query,
            "results": sorted(results, key=lambda x: x.get("combined_score", 0), reverse=True),
            "total_results": len(results),
        }

    def _calculate_context_relevance(
        self,
        result: Dict[str, Any],
        context: Dict[str, Any],
    ) -> float:
        """Calculate relevance based on case context."""
        score = 0.5
        
        if "category" in context:
            if result.get("category") == context["category"]:
                score += 0.3
        
        if "tags" in context:
            matching_tags = set(result.get("tags", [])) & set(context["tags"])
            score += len(matching_tags) * 0.1
        
        return min(1.0, score)


# Singleton instance
_engine: Optional[SearchEngine] = None


def get_search_engine() -> SearchEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = SearchEngine()
    return _engine


def reset_search_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None