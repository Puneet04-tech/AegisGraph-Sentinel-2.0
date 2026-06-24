"""Lightweight runtime threat model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class Threat:
    threat_id: str
    threat_type: str
    severity: str
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        severity = self.severity.lower()
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"Unsupported threat severity: {self.severity}")
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "metadata", dict(self.metadata or {}))
