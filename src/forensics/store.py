"""Thread-safe in-memory store for Digital Forensics entities."""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Dict, List, Optional

from .models import Evidence, Investigation, TimelineEvent, AttackChain


class _LRUDict(OrderedDict):
    """Bounded LRU dictionary to prevent memory leaks."""

    def __init__(self, maxsize: int = 10_000):
        self.maxsize = maxsize
        super().__init__()

    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        if len(self) > self.maxsize:
            self.popitem(last=False)

    def __getitem__(self, key):
        value = super().__getitem__(key)
        self.move_to_end(key)
        return value


class ForensicsStore:
    """Singleton in-memory store for Digital Forensics."""

    def __init__(self):
        self._lock = threading.RLock()
        self._evidence = _LRUDict(maxsize=20_000)
        self._investigations = _LRUDict(maxsize=5_000)
        self._events = _LRUDict(maxsize=50_000)
        self._chains = _LRUDict(maxsize=5_000)

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------
    def add_evidence(self, evidence: Evidence) -> None:
        with self._lock:
            self._evidence[evidence.id] = evidence

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        with self._lock:
            return self._evidence.get(evidence_id)

    def list_evidence_for_case(self, case_id: str) -> List[Evidence]:
        with self._lock:
            return [e for e in self._evidence.values() if e.case_id == case_id]

    # ------------------------------------------------------------------
    # Investigations
    # ------------------------------------------------------------------
    def add_investigation(self, investigation: Investigation) -> None:
        with self._lock:
            self._investigations[investigation.id] = investigation

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        with self._lock:
            return self._investigations.get(investigation_id)

    def list_investigations(self) -> List[Investigation]:
        with self._lock:
            return list(self._investigations.values())

    # ------------------------------------------------------------------
    # Timeline Events
    # ------------------------------------------------------------------
    def add_event(self, event: TimelineEvent) -> None:
        with self._lock:
            self._events[event.id] = event

    def get_events_for_investigation(self, investigation_id: str) -> List[TimelineEvent]:
        with self._lock:
            return [
                e for e in self._events.values()
                if e.investigation_id == investigation_id
            ]

    # ------------------------------------------------------------------
    # Attack Chains
    # ------------------------------------------------------------------
    def add_chain(self, chain: AttackChain) -> None:
        with self._lock:
            self._chains[chain.id] = chain

    def get_chain(self, chain_id: str) -> Optional[AttackChain]:
        with self._lock:
            return self._chains.get(chain_id)

    def get_chain_by_campaign(self, campaign_id: str) -> Optional[AttackChain]:
        with self._lock:
            for chain in self._chains.values():
                if chain.campaign_id == campaign_id:
                    return chain
            return None


# Singleton instance management
_forensics_store_instance: Optional[ForensicsStore] = None
_forensics_store_lock = threading.Lock()


def get_forensics_store() -> ForensicsStore:
    global _forensics_store_instance
    if _forensics_store_instance is None:
        with _forensics_store_lock:
            if _forensics_store_instance is None:
                _forensics_store_instance = ForensicsStore()
    return _forensics_store_instance

