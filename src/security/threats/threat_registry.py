"""Thread-safe in-memory runtime threat registry."""

from __future__ import annotations

import threading
from collections import Counter, deque
from typing import Deque, Dict, List, Optional

from .threat import Threat


class ThreatRegistry:
    def __init__(self, max_threats: int = 1000) -> None:
        self._threats: Deque[Threat] = deque(maxlen=max_threats)
        self._lock = threading.Lock()

    def add_threat(self, threat: Threat) -> Threat:
        with self._lock:
            self._threats.append(threat)
        return threat

    def get_threat(self, threat_id: str) -> Optional[Threat]:
        with self._lock:
            return next((threat for threat in self._threats if threat.threat_id == threat_id), None)

    def list_threats(self) -> List[Threat]:
        with self._lock:
            return list(self._threats)

    def count_by_severity(self) -> Dict[str, int]:
        with self._lock:
            return dict(Counter(threat.severity for threat in self._threats))
