"""
Real-time Streaming & Event Processing Models.

Data models for streams, events, windows, and alerts.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class WindowType(str, Enum):
    """Window types for stream processing."""
    TUMBLING = "TUMBLING"
    SLIDING = "SLIDING"
    SESSION = "SESSION"


class EventPriority(str, Enum):
    """Event priority levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class StreamEvent(BaseModel):
    """Stream event."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    source: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    priority: EventPriority = EventPriority.MEDIUM
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StreamWindow(BaseModel):
    """Stream window configuration."""
    window_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    window_type: WindowType
    size_seconds: int
    slide_seconds: Optional[int] = None
    session_timeout: Optional[int] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StreamAggregation(BaseModel):
    """Stream aggregation result."""
    aggregation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    stream_name: str
    window_id: str
    metric_name: str
    aggregation_type: str  # SUM, AVG, COUNT, MIN, MAX
    value: float
    window_start: datetime
    window_end: datetime
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StreamPattern(BaseModel):
    """Stream pattern detection."""
    pattern_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    pattern_type: str  # sequence, frequency, threshold, anomaly
    definition: Dict[str, Any] = Field(default_factory=dict)
    window_seconds: int
    threshold: float
    match_count: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StreamAlert(BaseModel):
    """Real-time alert."""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_type: str
    severity: EventPriority
    title: str
    description: str
    source_event_ids: List[str] = Field(default_factory=list)
    stream_name: str
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None


class StreamSubscription(BaseModel):
    """Stream subscription."""
    subscription_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    stream_name: str
    subscriber_id: str
    filter_criteria: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StreamMetrics(BaseModel):
    """Stream metrics."""
    metrics_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    stream_name: str
    events_per_second: float
    avg_latency_ms: float
    queue_depth: int
    active_subscribers: int
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))