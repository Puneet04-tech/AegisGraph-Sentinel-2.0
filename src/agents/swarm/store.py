"""
Shared Threat Intelligence Store
AegisGraph Sentinel - Swarm coordination.

A thread-safe in-memory store shared by all swarm agents so discoveries,
attack patterns, TTPs and findings from one agent are immediately visible
to every other agent and to the dashboard.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from .models import (
    AgentDescriptor,
    AttackPattern,
    SimulationFinding,
    ThreatDiscovery,
)


class ThreatIntelligenceStore:
    """Shared threat intelligence store for the swarm.

    Every write is guarded by a re-entrant lock so concurrent swarm agents
    can safely publish and consume intelligence without data races.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._agents: Dict[str, AgentDescriptor] = {}
        self._patterns: Dict[str, AttackPattern] = {}
        self._discoveries: Dict[str, ThreatDiscovery] = {}
        self._findings: Dict[str, SimulationFinding] = {}

    # ------------------------------------------------------------------
    # Agent registry
    # ------------------------------------------------------------------

    def register_agent(self, descriptor: AgentDescriptor) -> None:
        with self._lock:
            self._agents[descriptor.agent_id] = descriptor

    def get_agent(self, agent_id: str) -> Optional[AgentDescriptor]:
        with self._lock:
            return self._agents.get(agent_id)

    def get_agents(self) -> List[AgentDescriptor]:
        with self._lock:
            return list(self._agents.values())

    def get_agents_by_type(self, agent_type: Any) -> List[AgentDescriptor]:
        with self._lock:
            return [a for a in self._agents.values() if a.agent_type == agent_type]

    def update_agent(self, agent_id: str, **updates: Any) -> None:
        with self._lock:
            descriptor = self._agents.get(agent_id)
            if descriptor is None:
                return
            for key, value in updates.items():
                if hasattr(descriptor, key):
                    setattr(descriptor, key, value)

    # ------------------------------------------------------------------
    # Attack patterns
    # ------------------------------------------------------------------

    def add_pattern(self, pattern: AttackPattern) -> None:
        with self._lock:
            self._patterns[pattern.pattern_id] = pattern

    def add_patterns(self, patterns: List[AttackPattern]) -> int:
        with self._lock:
            for pattern in patterns:
                self._patterns[pattern.pattern_id] = pattern
            return len(patterns)

    def get_pattern(self, pattern_id: str) -> Optional[AttackPattern]:
        with self._lock:
            return self._patterns.get(pattern_id)

    def get_patterns(self) -> List[AttackPattern]:
        with self._lock:
            return list(self._patterns.values())

    def pattern_count(self) -> int:
        with self._lock:
            return len(self._patterns)

    # ------------------------------------------------------------------
    # Threat discoveries
    # ------------------------------------------------------------------

    def add_discovery(self, discovery: ThreatDiscovery) -> None:
        with self._lock:
            self._discoveries[discovery.discovery_id] = discovery

    def get_discoveries(self) -> List[ThreatDiscovery]:
        with self._lock:
            return list(self._discoveries.values())

    def discovery_count(self) -> int:
        with self._lock:
            return len(self._discoveries)

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(self, finding: SimulationFinding) -> None:
        with self._lock:
            self._findings[finding.finding_id] = finding

    def get_findings(self) -> List[SimulationFinding]:
        with self._lock:
            return list(self._findings.values())

    def finding_count(self) -> int:
        with self._lock:
            return len(self._findings)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "agents": len(self._agents),
                "attack_patterns": len(self._patterns),
                "discoveries": len(self._discoveries),
                "findings": len(self._findings),
            }


_store_lock = threading.Lock()
_shared_store: Optional[ThreatIntelligenceStore] = None


def get_threat_intelligence_store() -> ThreatIntelligenceStore:
    """Return the process-wide shared threat intelligence store."""
    global _shared_store
    with _store_lock:
        if _shared_store is None:
            _shared_store = ThreatIntelligenceStore()
        return _shared_store
