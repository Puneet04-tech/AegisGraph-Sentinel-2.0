"""
API Schemas for Data Lineage & Provenance Platform
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import Field

from src.api.schemas import BaseSchema


class SourceAttributionRequest(BaseSchema):
    """Request to create source attribution."""
    source_id: str = Field(description="Unique source identifier")
    source_type: str = Field(description="Type of data source")
    source_name: str = Field(description="Human-readable source name")
    trust_level: Optional[str] = Field(default="trusted", description="Trust level")


class LineageRecordCreateRequest(BaseSchema):
    """Request to create a lineage record."""
    record_type: str = Field(description="Type of record (intelligence, investigation, etc.)")
    data: Dict[str, Any] = Field(description="Record data payload")
    source: Optional[SourceAttributionRequest] = Field(default=None, description="Source attribution")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")


class LineageRecordResponse(BaseSchema):
    """Response containing lineage record data."""
    record_id: str
    record_type: str
    data: Dict[str, Any]
    source: Optional[Dict[str, Any]] = None
    provenance_chain: List[str] = Field(default_factory=list)
    created_at: str
    updated_at: str
    created_by: str
    version: int
    is_active: bool
    tags: List[str] = Field(default_factory=list)


class LineageLinkRequest(BaseSchema):
    """Request to link two records."""
    parent_id: str = Field(description="Parent record ID")
    child_id: str = Field(description="Child record ID")
    relationship_type: str = Field(description="Type of relationship")
    impact_level: Optional[str] = Field(default="medium", description="Impact level")


class ProvenanceChainResponse(BaseSchema):
    """Response containing provenance chain data."""
    chain_id: str
    root_record_id: str
    total_depth: int
    total_records: int
    chain_integrity: float
    records: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str
    verified_at: Optional[str] = None


class DependencyGraphResponse(BaseSchema):
    """Response containing dependency graph data."""
    graph_id: str
    root_record_id: str
    depth: int
    total_records: int
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str


class ImpactAnalysisResponse(BaseSchema):
    """Response containing impact analysis data."""
    analysis_id: str
    record_id: str
    impacted_records: List[str]
    impacted_entities: List[str]
    downstream_effects: Dict[str, Any]
    risk_score: float
    impact_level: str
    created_at: str


class LineageStatsResponse(BaseSchema):
    """Response containing lineage statistics."""
    total_records: int
    total_nodes: int
    total_edges: int
    average_depth: float
    max_depth: int
    records_by_type: Dict[str, int]
    sources_by_type: Dict[str, int]
    chain_integrity: float


class LineageQueryRequest(BaseSchema):
    """Request to query lineage records."""
    record_id: Optional[str] = Field(default=None, description="Filter by record ID")
    record_type: Optional[str] = Field(default=None, description="Filter by record type")
    source_type: Optional[str] = Field(default=None, description="Filter by source type")
    start_date: Optional[str] = Field(default=None, description="Start date filter")
    end_date: Optional[str] = Field(default=None, description="End date filter")
    tags: List[str] = Field(default_factory=list, description="Filter by tags")
    depth_limit: int = Field(default=10, description="Maximum depth to traverse")
    include_derivatives: bool = Field(default=True, description="Include derivative records")
    include_ancestors: bool = Field(default=True, description="Include ancestor records")


class LineageReportResponse(BaseSchema):
    """Response containing lineage report data."""
    record: Dict[str, Any]
    provenance_chain: Optional[Dict[str, Any]] = None
    dependency_graph: Optional[Dict[str, Any]] = None
    impact_analysis: Optional[Dict[str, Any]] = None
    statistics: Dict[str, Any]
    generated_at: str


class TraceabilityRecordResponse(BaseSchema):
    """Response containing traceability record data."""
    record_id: str
    action: str
    actor: str
    timestamp: str
    details: Dict[str, Any]
    previous_state: Optional[str] = None
    new_state: Optional[str] = None


class LineageDashboardResponse(BaseSchema):
    """Response containing lineage dashboard data."""
    statistics: Dict[str, Any]
    recent_records: List[Dict[str, Any]]
    top_sources: List[Dict[str, Any]]
    integrity_score: float
