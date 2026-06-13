"""Security Intelligence Search Engine - Data Models"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional  # noqa: F401
from pydantic import BaseModel, Field
import uuid


class SearchQuery(BaseModel):
    """Search query."""
    query_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query: str
    filters: Dict[str, Any] = Field(default_factory=dict)
    search_type: str = "SEMANTIC"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SearchResult(BaseModel):
    """Search result."""
    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_id: str
    entity_type: str
    entity_id: str
    title: str
    description: str
    relevance_score: float = 0.0
    highlights: List[str] = Field(default_factory=list)


class IndexEntry(BaseModel):
    """Index entry."""
    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: str
    entity_id: str
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    indexed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SearchRanking(BaseModel):
    """Search ranking."""
    ranking_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    result_id: str
    rank: int = 0
    score_components: Dict[str, float] = Field(default_factory=dict)


class SearchAnalytics(BaseModel):
    """Search analytics."""
    total_queries: int = 0
    avg_results_per_query: float = 0.0
    top_searches: List[str] = Field(default_factory=list)
    avg_latency_ms: float = 0.0
