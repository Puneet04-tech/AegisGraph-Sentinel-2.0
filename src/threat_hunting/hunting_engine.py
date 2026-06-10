"""
Threat Hunting Engine for AI Threat Hunting
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from .models import ThreatHunt, HuntState, HuntResult
from .store import ThreatHuntingStore, get_store


class ThreatHuntingEngine:
    """Engine to configure, execute, and track proactive threat hunts."""

    def __init__(self, store: Optional[ThreatHuntingStore] = None):
        self.store = store or get_store()

    def start_hunt(
        self,
        name: str,
        description: str,
        query_criteria: Dict[str, Any],
        created_by: str = "analyst",
    ) -> ThreatHunt:
        """Create and start a threat hunt run."""
        hunt = ThreatHunt(
            name=name,
            description=description,
            query_criteria=query_criteria,
            state=HuntState.PENDING,
            created_by=created_by,
        )
        self.store.add_hunt(hunt)
        self.execute_hunt(hunt.hunt_id)
        return hunt

    def execute_hunt(self, hunt_id: str):
        """Execute the query criteria matching against currently stored entities."""
        hunt = self.store.get_hunt(hunt_id)
        if not hunt:
            return

        self.store.update_hunt_state(
            hunt_id,
            state=HuntState.RUNNING,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        try:
            criteria = hunt.query_criteria
            score_threshold = criteria.get("min_threat_score", 0.0)
            indicator_types = criteria.get("indicator_types", [])

            findings_count = 0

            # Get all cached entity scores
            for entity_id in list(self.store.scores.keys()):
                score_data = self.store.get_threat_score(entity_id)
                if not score_data:
                    continue

                # Filter by threat score threshold
                if score_data.score >= score_threshold:
                    # Filter by indicator type if specified
                    match = True
                    if indicator_types:
                        match = False
                        # Check if any active indicator matches requested types
                        for ind_id in score_data.active_indicators:
                            ind = self.store.get_indicator(ind_id)
                            if ind and ind.indicator_type.value in indicator_types:
                                match = True
                                break

                    if match:
                        result = HuntResult(
                            hunt_id=hunt_id,
                            matched_entity_id=entity_id,
                            matched_entity_type=score_data.entity_type,
                            threat_score=score_data.score,
                            indicators=score_data.active_indicators,
                            details={
                                "breakdown": score_data.breakdown,
                                "severity": score_data.severity.value,
                            },
                        )
                        self.store.add_result(result)
                        findings_count += 1

            self.store.update_hunt_state(
                hunt_id,
                state=HuntState.COMPLETED,
                completed_at=datetime.now(timezone.utc).isoformat(),
                findings_count=findings_count,
            )

        except Exception as e:
            self.store.update_hunt_state(
                hunt_id,
                state=HuntState.FAILED,
                completed_at=datetime.now(timezone.utc).isoformat(),
                error_message=str(e),
            )
