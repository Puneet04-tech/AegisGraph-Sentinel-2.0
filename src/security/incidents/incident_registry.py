"""Thread-safe in-memory security incident registry."""

from __future__ import annotations

import threading
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

from .incident import Incident


class IncidentRegistry:
    def __init__(self, max_incidents: int = 1000) -> None:
        self._incidents: Deque[Incident] = deque(maxlen=max_incidents)
        self._lock = threading.Lock()

    def create_incident(
        self,
        incident_type: str,
        severity: str,
        metadata: Optional[Dict[str, Any]] = None,
        contained: bool = False,
    ) -> Incident:
        incident = Incident(
            incident_id=str(uuid.uuid4()),
            incident_type=incident_type,
            severity=severity.lower(),
            created_at=datetime.now(timezone.utc),
            metadata=dict(metadata or {}),
            contained=contained,
        )
        with self._lock:
            self._incidents.append(incident)
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        with self._lock:
            return next((incident for incident in self._incidents if incident.incident_id == incident_id), None)

    def list_incidents(self) -> List[Incident]:
        with self._lock:
            return list(self._incidents)

    def count_by_severity(self) -> Dict[str, int]:
        with self._lock:
            return dict(Counter(incident.severity for incident in self._incidents))
