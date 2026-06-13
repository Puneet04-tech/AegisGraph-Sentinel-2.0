"""Performance Optimization Models"""
from __future__ import annotations
from datetime import datetime, timezone  # noqa: F401
from typing import Any, Dict, List, Optional  # noqa: F401
from pydantic import BaseModel, Field
import uuid


class PerformanceMetrics(BaseModel):
    """Performance metrics."""
    metrics_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    component: str
    latency_ms: float = 0.0
    throughput: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OptimizationRule(BaseModel):
    """Optimization rule."""
    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    condition: Dict[str, Any] = {}
    action: Dict[str, Any] = {}
    enabled: bool = True


class Benchmark(BaseModel):
    """Benchmark result."""
    benchmark_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    score: float = 0.0
    config: Dict[str, Any] = {}


class PerformanceReport(BaseModel):
    """Performance report."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    metrics_summary: Dict[str, float] = {}
    recommendations: List[str] = []
