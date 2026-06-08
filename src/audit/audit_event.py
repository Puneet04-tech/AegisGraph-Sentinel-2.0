"""Lightweight audit event model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    event_type: str
    severity: str
    source: str
    correlation_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)
