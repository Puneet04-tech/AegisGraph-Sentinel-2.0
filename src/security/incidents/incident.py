"""Security incident model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict


@dataclass
class Incident:
    incident_id: str
    incident_type: str
    severity: str
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    contained: bool = False
