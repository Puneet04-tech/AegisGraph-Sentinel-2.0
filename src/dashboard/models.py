"""Executive Command Dashboard Models"""
from __future__ import annotations
from datetime import datetime, timezone  # noqa: F401
from typing import Any, Dict, List, Optional  # noqa: F401
from pydantic import BaseModel, Field
import uuid


class Widget(BaseModel):
    """Dashboard widget."""
    widget_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    widget_type: str
    title: str
    config: Dict[str, Any] = {}
    position: int = 0


class Dashboard(BaseModel):
    """Executive dashboard."""
    dashboard_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    widgets: List[Widget] = []
    owner: str = "system"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DashboardMetrics(BaseModel):
    """Dashboard metrics."""
    total_dashboards: int = 0
    total_widgets: int = 0
    active_views: int = 0
