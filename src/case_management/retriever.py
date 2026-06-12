"""
Case Retriever for Semantic Similarity Search

Combines embedding generation with vector store to provide high-level
case similarity search capabilities.
"""

from typing import Dict, List, Optional
from datetime import datetime
import logging

from src.case_management.vector_store import VectorStore, SearchResult
from src.embeddings import get_embedder, CaseEmbedder

logger = logging.getLogger(__name__)


class CaseRetriever:
    """
    High-level interface for finding similar fraud cases by semantic similarity.
    
    Coordinates between the embedding generator and vector store to provide
    a clean API for case retrieval.
    
    Args:
        embedder: CaseEmbedder instance (or create new)
        vector_store: VectorStore instance (or create new)
        embedding_dim: Dimension of embeddings
        similarity_threshold: Minimum similarity score to return
    """
    
    def __init__(
        self,
        embedder: Optional[CaseEmbedder] = None,
        vector_store: Optional[VectorStore] = None,
        embedding_dim: int = 768,
        similarity_threshold: float = 0.5,
    ):
        self.embedder = embedder or get_embedder(embedding_dim=embedding_dim)
        self.vector_store = vector_store or VectorStore(
            embedding_dim=embedding_dim,
            similarity_threshold=0.0,
        )
        self.embedding_dim = embedding_dim
        self.similarity_threshold = similarity_threshold

        self._case_registry = {}
    
    def index_case(
        self,
        case_id: str,
        explanation: Dict,
        metadata: Optional[Dict] = None,
    ) -> None:
        """
        Add a fraud case to the retrieval index.
        
        Args:
            case_id: Unique case identifier
            explanation: Fraud case explanation dict from Aegis-Oracle
            metadata: Optional metadata (date, priority, status, etc.)
        
        Example:
            retriever.index_case(
                case_id="CASE_123",
                explanation={
                    "summary": "Suspicious transfer detected",
                    "explanation": "Account X sent $10k to new recipient...",
                    "factors": {...}
                },
                metadata={
                    "date": "2026-06-10",
                    "priority": "HIGH",
                    "status": "RESOLVED"
                }
            )
        """
        try:
            # Generate embedding
            embedding = self.embedder.embed_case_explanation(explanation)
            
            # Prepare metadata with explanation text for reference
            full_metadata = metadata or {}
            full_metadata.update({
                "indexed_at": datetime.utcnow().isoformat(),
                "summary": explanation.get("summary", ""),
            })
            
            # Add to vector store
            self.vector_store.add(case_id, embedding, full_metadata)

            # Store full case information for intelligence generation
            self._case_registry[case_id] = {
                "explanation": explanation,
                "metadata": full_metadata,
            }

            logger.info(f"Indexed case {case_id}")
        
        except Exception as e:
            logger.error(f"Error indexing case {case_id}: {e}")
            raise
    
    def index_cases_batch(
        self,
        cases: List[Dict],
    ) -> None:
        """
        Batch index multiple fraud cases.
        
        Args:
            cases: List of dicts with keys:
                - case_id: Unique identifier
                - explanation: Fraud explanation dict
                - metadata: Optional metadata dict
        
        Example:
            retriever.index_cases_batch([
                {
                    "case_id": "CASE_1",
                    "explanation": {...},
                    "metadata": {"priority": "HIGH"}
                },
                {
                    "case_id": "CASE_2",
                    "explanation": {...},
                    "metadata": {"priority": "LOW"}
                }
            ])
        """
        for case in cases:
            self.index_case(
                case_id=case["case_id"],
                explanation=case["explanation"],
                metadata=case.get("metadata"),
            )
        
        logger.info(f"Indexed {len(cases)} cases")
    
    def find_similar(
        self,
        query_text: str,
        k: int = 10,
        threshold: Optional[float] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> List[Dict]:
        """
        Find similar cases by text similarity with optional metadata filtering.
        """
        try:
            # Generate embedding for query
            query_embedding = self.embedder.embed_text(query_text)

            # Search vector store
            search_results = self.vector_store.query(
                embedding=query_embedding,
                k=max(k * 3, k),  # over-fetch to allow filtering
                threshold=threshold,
            )

            filtered_results = []

            for result in search_results:
                metadata = result.metadata or {}

                # Status filter
                if status and metadata.get("status") != status:
                    continue

                # Priority filter
                if priority and metadata.get("priority") != priority:
                    continue

                # Date range filter
                case_date = metadata.get("date")

                if start_date and case_date and case_date < start_date:
                    continue

                if end_date and case_date and case_date > end_date:
                    continue

                filtered_results.append(
                    {
                        "case_id": result.case_id,
                        "similarity": result.similarity_score,
                        "similarity_percent": f"{result.similarity_score * 100:.1f}%",
                        "metadata": metadata,
                    }
                )

            results = filtered_results[:k]

            logger.info(
                f"Found {len(results)} similar cases "
                f"(query: {query_text[:50]}...)"
            )

            return results

        except Exception as e:
            logger.error(f"Error finding similar cases: {e}")
            raise
    
    def find_similar_by_case(
        self,
        case_id: str,
        k: int = 10,
        exclude_self: bool = True,
        threshold: Optional[float] = None,
    ) -> List[Dict]:
        """
        Find cases similar to an existing case.
        
        Args:
            case_id: Reference case identifier
            k: Number of results (or k+1 if excluding self)
            exclude_self: Whether to exclude the query case from results
            threshold: Override similarity threshold
        
        Returns:
            List of similar cases (excluding the query case if exclude_self=True)
        """
        # Retrieve the case's embedding
        embedding_tuple = self.vector_store.get(case_id)
        
        if embedding_tuple is None:
            logger.warning(f"Case {case_id} not found in vector store")
            return []
        
        embedding, _ = embedding_tuple
        
        # Search (request k+1 if excluding self)
        search_k = k + 1 if exclude_self else k
        search_results = self.vector_store.query(
            embedding=embedding,
            k=search_k,
            threshold=threshold,
        )
        
        # Filter out self if requested
        if exclude_self:
            search_results = [r for r in search_results if r.case_id != case_id]
        
        # Trim to requested k
        search_results = search_results[:k]
        
        # Format
        results = [
            {
                "case_id": result.case_id,
                "similarity": result.similarity_score,
                "similarity_percent": f"{result.similarity_score * 100:.1f}%",
                "metadata": result.metadata,
            }
            for result in search_results
        ]
        
        logger.info(f"Found {len(results)} similar cases for {case_id}")
        return results
    
    def find_similar_by_explanation(
        self,
        explanation: Dict,
        k: int = 10,
        threshold: Optional[float] = None,
    ) -> List[Dict]:
        """
        Find similar cases by fraud explanation dict.
        
        Args:
            explanation: Fraud explanation dict
            k: Number of results
            threshold: Override similarity threshold
        
        Returns:
            List of similar cases
        """
        # Generate embedding for explanation
        query_embedding = self.embedder.embed_case_explanation(explanation)
        
        # Search
        search_results = self.vector_store.query(
            embedding=query_embedding,
            k=k,
            threshold=threshold,
        )
        
        # Format
        results = [
            {
                "case_id": result.case_id,
                "similarity": result.similarity_score,
                "similarity_percent": f"{result.similarity_score * 100:.1f}%",
                "metadata": result.metadata,
            }
            for result in search_results
        ]
        
        return results
    
    def update_case_metadata(
        self,
        case_id: str,
        metadata: Dict,
    ) -> bool:
        """
        Update metadata for an indexed case.
        
        Args:
            case_id: Case identifier
            metadata: Updated metadata dict (merges with existing)
        
        Returns:
            True if updated, False if not found
        """
        return self.vector_store.update_metadata(case_id, metadata)
    
    def remove_case(self, case_id: str) -> bool:
        """
        Remove a case from the index.
        """
        removed = self.vector_store.remove(case_id)

        if removed:
            self._case_registry.pop(case_id, None)

        return removed
    
    def get_stats(self) -> Dict:
        """
        Get retrieval system statistics.
        
        Returns:
            Dict with store stats and embedder cache info
        """
        return {
            "vector_store": self.vector_store.get_stats(),
            "embedder_cache": self.embedder.get_cache_stats(),
        }
    
    def clear_all(self) -> None:
        """Clear all indexed cases and caches."""
        self.vector_store.clear()
        self.embedder.clear_cache()
        self._case_registry.clear()

        logger.info("Cleared all indexed cases and caches")
        
    def get_investigation_insights(
        self,
        case_id: str,
        top_k: int = 5,
    ) -> Dict:
        """
        Generate investigation intelligence for a fraud case.

        Returns:
            Related cases
            Common fraud patterns
            Investigation recommendations
            Contextual intelligence
        """
        if case_id not in self._case_registry:
            raise ValueError(f"Case not found: {case_id}")

        case_data = self._case_registry[case_id]

        similar_cases = self.find_similar_by_case(
            case_id=case_id,
            k=top_k,
            exclude_self=True,
        )

        priorities = []
        statuses = []

        for case in similar_cases:
            metadata = case.get("metadata", {})

            if metadata.get("priority"):
                priorities.append(metadata["priority"])

            if metadata.get("status"):
                statuses.append(metadata["status"])

        recommendations = []

        if len(similar_cases) >= 3:
            recommendations.append(
                "Multiple related fraud cases detected. Escalate investigation."
            )

        if "CRITICAL" in priorities:
            recommendations.append(
                "Related critical-priority cases identified."
            )

        if not recommendations:
            recommendations.append(
                "Continue monitoring for recurring fraud patterns."
            )

        return {
            "case_id": case_id,
            "similar_case_count": len(similar_cases),
            "related_cases": similar_cases,
            "common_priorities": list(set(priorities)),
            "common_statuses": list(set(statuses)),
            "recommendations": recommendations,
            "investigation_summary": (
                f"Found {len(similar_cases)} semantically related fraud cases."
            ),
        }