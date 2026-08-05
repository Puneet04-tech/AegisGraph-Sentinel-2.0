"""
Swarm Dashboard
AegisGraph Sentinel - Swarm status and simulation coverage dashboard.

Aggregates live swarm state into snapshots suitable for the Streamlit UI:
active agents, discovered threats, simulation coverage metrics and model
improvement tracking over time.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .models import SwarmAgentStatus
from .store import ThreatIntelligenceStore, get_threat_intelligence_store


class SwarmDashboard:
    """Read-model for the simulation swarm UI."""

    def __init__(
        self,
        coordinator: Any = None,
        store: Optional[ThreatIntelligenceStore] = None,
        feedback_loop: Any = None,
        intelligence_graph: Any = None,
    ) -> None:
        self._coordinator = coordinator
        self._store = store or get_threat_intelligence_store()
        self._feedback_loop = feedback_loop
        self._intelligence_graph = intelligence_graph

    def agent_status(self) -> Dict[str, Any]:
        """Real-time agent status grouped by lifecycle state."""
        agents = self._store.get_agents() if self._coordinator is None else list(
            self._coordinator.agents.values()
        )
        counts = {status.value: 0 for status in SwarmAgentStatus}
        for agent in agents:
            counts[agent.status.value] = counts.get(agent.status.value, 0) + 1
        return {
            "active_agents": len(agents),
            "by_status": counts,
            "running": counts.get(SwarmAgentStatus.RUNNING.value, 0),
            "idle": counts.get(SwarmAgentStatus.IDLE.value, 0),
        }

    def threat_events(self) -> Dict[str, Any]:
        """Threat discovery events published to the shared store."""
        discoveries = self._store.get_discoveries()
        return {
            "total_discoveries": len(discoveries),
            "fraud_rings": sum(1 for d in discoveries if d.discovery_type == "fraud_ring"),
            "events": [
                {
                    "id": d.discovery_id,
                    "type": d.discovery_type,
                    "score": d.score,
                    "members": len(d.member_entities),
                }
                for d in discoveries
            ],
        }

    def coverage_metrics(self) -> Dict[str, Any]:
        """Simulation coverage and threat intelligence volume."""
        patterns = self._store.get_patterns()
        stats = {"attack_patterns": len(patterns)}
        if self._intelligence_graph is not None:
            stats.update(self._intelligence_graph.stats())
        return stats

    def improvement_trends(self) -> Dict[str, Any]:
        """Model improvement tracking from the feedback loop."""
        if self._feedback_loop is None:
            return {
                "delta": 0.0,
                "latest": 0.0,
                "retraining_events": 0,
            }
        return self._feedback_loop.improvement_trend()

    def snapshot(self) -> Dict[str, Any]:
        """Full dashboard snapshot for the Streamlit UI."""
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "agents": self.agent_status(),
            "threats": self.threat_events(),
            "coverage": self.coverage_metrics(),
            "improvement": self.improvement_trends(),
        }
