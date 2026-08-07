"""
Feedback Loop
AegisGraph Sentinel - Training pipeline integration from simulation findings.

Converts simulation findings and threat-hunting discoveries into retraining
signals for the HTGNN fraud detection model. When simulation coverage drops
below a configured threshold, the loop triggers model retraining and tracks
improvement over time.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from .models import AttackPattern, SimulationFinding, ThreatDiscovery


class FeedbackLoop:
    """Feeds simulation findings back into the training pipeline.

    Attributes:
        retraining_threshold: Coverage below this value triggers retraining.
        store: Shared threat intelligence store (optional).
    """

    def __init__(
        self,
        retraining_threshold: float = 0.6,
        store: Any = None,
    ) -> None:
        self.retraining_threshold = retraining_threshold
        self._store = store
        self._retraining_events: List[Dict[str, Any]] = []
        self._coverage_history: List[Dict[str, Any]] = []
        self._precision_history: List[float] = []

    def compute_coverage(self, graph: Dict[str, Any]) -> Dict[str, Any]:
        """Compute simulation coverage over the entity graph.

        Coverage is the fraction of graph entities referenced by at least one
        known attack pattern or stored discovery.

        Returns:
            Dict with ``coverage``, ``covered_entities``, ``total_entities``.
        """
        nodes = graph.get("nodes", [])
        total = len(nodes)
        if total == 0:
            return {"coverage": 0.0, "covered_entities": 0, "total_entities": 0}

        known_entities = self._known_entity_ids()
        covered = sum(1 for node in nodes if node.get("id") in known_entities)
        coverage = covered / total
        entry = {
            "coverage": round(coverage, 4),
            "covered_entities": covered,
            "total_entities": total,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._coverage_history.append(entry)
        return entry

    def maybe_trigger_retraining(self, coverage: Dict[str, Any]) -> bool:
        """Trigger retraining when coverage falls below the threshold.

        Returns:
            True if a retraining event was recorded.
        """
        value = coverage.get("coverage", 0.0)
        if value < self.retraining_threshold:
            self._retraining_events.append({
                "triggered_at": datetime.now(timezone.utc).isoformat(),
                "coverage": value,
                "threshold": self.retraining_threshold,
                "reason": "simulation coverage below configured threshold",
            })
            return True
        return False

    def record_precision(self, precision: float) -> None:
        """Record a hunting precision measurement for trend tracking."""
        self._precision_history.append(round(float(precision), 4))

    def retraining_event_count(self) -> int:
        return len(self._retraining_events)

    def improvement_trend(self) -> Dict[str, Any]:
        """Summarize model improvement over recorded precision history."""
        if not self._precision_history:
            return {
                "delta": 0.0,
                "start": 0.0,
                "latest": 0.0,
                "retraining_events": self.retraining_event_count(),
                "coverage_history_points": len(self._coverage_history),
            }
        start = self._precision_history[0]
        latest = self._precision_history[-1]
        return {
            "delta": round(latest - start, 4),
            "start": start,
            "latest": latest,
            "retraining_events": self.retraining_event_count(),
            "coverage_history_points": len(self._coverage_history),
        }

    def _known_entity_ids(self) -> set:
        known: set = set()
        if self._store is not None:
            for pattern in self._store.get_patterns():
                if isinstance(pattern, AttackPattern):
                    known.update(pattern.indicators)
            for discovery in self._store.get_discoveries():
                if isinstance(discovery, ThreatDiscovery):
                    known.update(discovery.member_entities)
            for finding in self._store.get_findings():
                if isinstance(finding, SimulationFinding):
                    known.update(finding.entity_ids)
        return known

    def build_training_signal(self, discoveries: List[ThreatDiscovery]) -> Dict[str, Any]:
        """Package discoveries into a signal the training pipeline consumes."""
        return {
            "positive_samples": sum(len(d.member_entities) for d in discoveries),
            "discoveries": len(discoveries),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "action": "augment_training_data",
        }
