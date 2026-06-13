"""Universal Data Connector Models"""
from __future__ import annotations
from datetime import datetime, timezone  # noqa: F401
from typing import Any, Dict, List, Optional  # noqa: F401
from pydantic import BaseModel, Field
import uuid


class DataSource(BaseModel):
    """Data source."""
    source_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    source_type: str
    config: Dict[str, Any] = {}
    enabled: bool = True


class DataConnector(BaseModel):
    """Data connector."""
    connector_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    source_types: List[str] = []
    transformation_rules: List[Dict[str, Any]] = []


class ConnectorMetrics(BaseModel):
    """Connector metrics."""
    total_connectors: int = 0
    active_sources: int = 0
