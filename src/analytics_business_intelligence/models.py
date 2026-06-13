"""
Advanced Analytics & Business Intelligence Models.

Data models for analytics, BI dashboards, KPI tracking, and reporting automation.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class MetricType(str, Enum):
    """Metric types."""
    COUNTER = "COUNTER"
    GAUGE = "GAUGE"
    RATE = "RATE"
    PERCENTAGE = "PERCENTAGE"
    CURRENCY = "CURRENCY"


class AggregationType(str, Enum):
    """Aggregation types."""
    SUM = "SUM"
    AVG = "AVG"
    MIN = "MIN"
    MAX = "MAX"
    COUNT = "COUNT"
    MEDIAN = "MEDIAN"


class ReportSchedule(str, Enum):
    """Report schedules."""
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"
    MONTHLY = "MONTHLY"
    QUARTERLY = "QUARTERLY"
    ON_DEMAND = "ON_DEMAND"


class DataCube(BaseModel):
    """Analytical data cube for multi-dimensional analysis."""
    cube_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    dimensions: List[str] = Field(default_factory=list)
    measures: List[str] = Field(default_factory=list)
    facts: int = 0
    aggregations: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MetricDefinition(BaseModel):
    """Metric definition for analytics."""
    metric_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    metric_type: MetricType
    aggregation: AggregationType
    category: str
    unit: str
    formula: Optional[str] = None
    dimensions: List[str] = Field(default_factory=list)
    thresholds: Dict[str, float] = Field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MetricValue(BaseModel):
    """Metric value record."""
    value_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    metric_id: str
    value: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    dimensions: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KPI(BaseModel):
    """Key Performance Indicator."""
    kpi_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    metric_id: str
    target_value: float
    warning_threshold: float
    critical_threshold: float
    current_value: Optional[float] = None
    previous_value: Optional[float] = None
    change_percent: Optional[float] = None
    status: str = "ON_TARGET"  # ON_TARGET, WARNING, CRITICAL
    category: str
    owner: Optional[str] = None
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TrendAnalysis(BaseModel):
    """Trend analysis result."""
    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    metric_name: str
    period_start: datetime
    period_end: datetime
    direction: str  # increasing, decreasing, stable
    slope: float
    volatility: float
    forecast_values: List[float] = Field(default_factory=list)
    confidence_interval: tuple = (0.0, 0.0)
    seasonality_detected: bool = False
    anomaly_detected: bool = False
    anomaly_points: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CorrelationResult(BaseModel):
    """Correlation analysis result."""
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    variable_a: str
    variable_b: str
    correlation_coefficient: float  # -1 to 1
    p_value: float
    significance: str  # HIGH, MEDIUM, LOW
    interpretation: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SegmentAnalysis(BaseModel):
    """Customer/entity segment analysis."""
    segment_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    segment_name: str
    segment_definition: Dict[str, Any] = Field(default_factory=dict)
    size: int
    percentage: float
    metrics: Dict[str, float] = Field(default_factory=dict)
    risk_distribution: Dict[str, int] = Field(default_factory=dict)
    top_characteristics: List[str] = Field(default_factory=list)


class CohortAnalysis(BaseModel):
    """Cohort analysis result."""
    cohort_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cohort_name: str
    cohort_definition: Dict[str, Any] = Field(default_factory=dict)
    retention_rates: List[float] = Field(default_factory=list)
    period_count: int
    average_retention: float
    churn_rate: float
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BIChart(BaseModel):
    """Business intelligence chart configuration."""
    chart_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    chart_type: str  # bar, line, pie, scatter, heatmap, etc.
    data_source: str
    x_axis: str
    y_axis: str
    series: List[str] = Field(default_factory=list)
    filters: Dict[str, Any] = Field(default_factory=dict)
    visualization_options: Dict[str, Any] = Field(default_factory=dict)


class BIDashboard(BaseModel):
    """Business intelligence dashboard."""
    dashboard_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    charts: List[BIChart] = Field(default_factory=list)
    kpis: List[str] = Field(default_factory=list)  # KPI IDs
    layout: Dict[str, Any] = Field(default_factory=dict)
    refresh_interval: int = 300  # seconds
    filters: Dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = None
    is_shared: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AutomatedReport(BaseModel):
    """Automated report configuration."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    schedule: ReportSchedule
    report_type: str
    content_config: Dict[str, Any] = Field(default_factory=dict)
    recipients: List[str] = Field(default_factory=list)
    format: str = "PDF"  # PDF, HTML, CSV, EXCEL
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DataAggregation(BaseModel):
    """Pre-computed data aggregation."""
    aggregation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    query: str
    dimensions: List[str] = Field(default_factory=list)
    measures: List[str] = Field(default_factory=list)
    result_count: int
    cached_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime


class Insight(BaseModel):
    """Business insight from analytics."""
    insight_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    insight_type: str  # trend, anomaly, correlation, segment
    severity: str  # critical, warning, info
    data_points: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None


# Store singleton
_store = None


def get_analytics_store():
    """Get or create the analytics store singleton."""
    global _store
    if _store is None:
        from .store import AnalyticsStore
        _store = AnalyticsStore()
    return _store