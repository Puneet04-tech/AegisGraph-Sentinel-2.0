"""
Security Data Fabric Models.

Universal security data model for the enterprise data fabric.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class DataClassification(str, Enum):
    """Data classification levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class DataDomain(str, Enum):
    """Security data domains."""
    FRAUD = "fraud"
    AML = "aml"
    CYBER = "cyber"
    THREAT_INTEL = "threat_intel"
    COMPLIANCE = "compliance"
    INVESTIGATION = "investigation"
    RISK = "risk"


class DataFormat(str, Enum):
    """Supported data formats."""
    JSON = "json"
    CSV = "csv"
    PARQUET = "parquet"
    AVRO = "avro"
    PROTOBUF = "protobuf"


class LineageType(str, Enum):
    """Lineage relationship types."""
    DERIVED_FROM = "derived_from"
    TRANSFORMED_FROM = "transformed_from"
    COPIED_FROM = "copied_from"
    REFERENCES = "references"
    IMPACTS = "impacts"


@dataclass
class DataSchema:
    """Schema definition for data assets."""
    schema_id: str
    name: str
    version: str
    domain: DataDomain
    fields: List[Dict[str, Any]]
    classification: DataClassification = DataClassification.INTERNAL
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DataAsset:
    """Security data asset."""
    asset_id: str
    name: str
    description: str
    domain: DataDomain
    schema_id: Optional[str] = None
    classification: DataClassification = DataClassification.INTERNAL
    source_system: Optional[str] = None
    owner: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    row_count: int = 0
    size_bytes: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed: Optional[datetime] = None


@dataclass
class DataCatalogEntry:
    """Entry in the metadata catalog."""
    entry_id: str
    asset_id: str
    schema_id: str
    domain: DataDomain
    classification: DataClassification
    description: str
    tags: List[str] = field(default_factory=list)
    business_owner: Optional[str] = None
    technical_owner: Optional[str] = None
    quality_score: float = 1.0
    usage_count: int = 0
    last_queried: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class LineageRecord:
    """Data lineage record."""
    record_id: str
    source_asset_id: str
    target_asset_id: str
    lineage_type: LineageType
    transformation_logic: Optional[str] = None
    confidence: float = 1.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DataPolicy:
    """Data governance policy."""
    policy_id: str
    name: str
    description: str
    domain: DataDomain
    classification: DataClassification
    rules: List[Dict[str, Any]]
    enforced: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DataQualityReport:
    """Data quality assessment report."""
    report_id: str
    asset_id: str
    completeness_score: float
    accuracy_score: float
    consistency_score: float
    timeliness_score: float
    overall_score: float
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class QueryRequest:
    """Federated query request."""
    query_id: str
    query_string: str
    domains: List[DataDomain] = field(default_factory=list)
    classification: Optional[DataClassification] = None
    timeout_seconds: int = 30
    limit: int = 1000


@dataclass
class QueryResult:
    """Query result."""
    result_id: str
    query_id: str
    data: List[Dict[str, Any]]
    row_count: int
    execution_time_ms: float
    sources_queried: List[str] = field(default_factory=list)
    cached: bool = False


@dataclass
class AuditEvent:
    """Audit event for data fabric operations."""
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    success: bool = True


@dataclass
class DataDistribution:
    """Data distribution record."""
    distribution_id: str
    source_asset_id: str
    target_systems: List[str] = field(default_factory=list)
    frequency: str = "on_demand"
    last_distributed: Optional[datetime] = None
    status: str = "active"