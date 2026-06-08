"""Timeline Engine for chronological event ordering and reconstruction."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from src.case_management import get_case_store
from .models import TimelineEvent
from .store import get_forensics_store

logger = logging.getLogger("forensics.timeline_engine")


class TimelineEngine:
    """Orchestrates forensic timeline reconstruction by aggregating history from cases, comments, evidence, and custom events."""

    def __init__(self) -> None:
        self.forensics_store = get_forensics_store()
        self.case_store = get_case_store()

    def build_timeline(self, investigation_id: str) -> List[TimelineEvent]:
        """Aggregate all timeline events for a given investigation, sorted chronologically."""
        investigation = self.forensics_store.get_investigation(investigation_id)
        if not investigation:
            logger.warning(f"Investigation ID '{investigation_id}' not found.")
            return []

        events: List[TimelineEvent] = []

        # 1. Fetch manual events registered directly to the investigation
        events.extend(self.forensics_store.get_events_for_investigation(investigation_id))

        # 2. Iterate through all linked cases to build case-specific timelines
        for case_id in investigation.case_ids:
            case = self.case_store.get_case(case_id)
            if not case:
                continue

            # Case creation event
            events.append(
                TimelineEvent(
                    investigation_id=investigation_id,
                    event_type="CASE_LINKED",
                    entity_id=case_id,
                    description=f"Case '{case_id}' linked to investigation. Risk Score: {case.risk_score}.",
                    timestamp=case.created_at,
                    metadata={
                        "transaction_id": case.transaction_id,
                        "risk_score": case.risk_score,
                        "decision": case.decision,
                        "priority": case.priority.value,
                    }
                )
            )

            # Get case audit timeline from case store
            audit_events = self.case_store.get_timeline(case_id)
            for audit in audit_events:
                events.append(
                    TimelineEvent(
                        investigation_id=investigation_id,
                        event_type="CASE_AUDIT",
                        entity_id=audit.event_id,
                        description=f"Case Audit: {audit.action} by {audit.analyst_id}",
                        timestamp=audit.timestamp,
                        metadata={
                            "action": audit.action,
                            "analyst_id": audit.analyst_id,
                            "old_value": audit.old_value,
                            "new_value": audit.new_value,
                        }
                    )
                )

            # Get case comments
            comments = self.case_store.get_comments(case_id)
            for comment in comments:
                events.append(
                    TimelineEvent(
                        investigation_id=investigation_id,
                        event_type="CASE_COMMENT",
                        entity_id=comment.comment_id,
                        description=f"Analyst {comment.analyst_id} left a note: '{comment.text[:40]}...'",
                        timestamp=comment.created_at,
                        metadata={
                            "analyst_id": comment.analyst_id,
                            "text": comment.text,
                        }
                    )
                )

            # Get case evidence (from case management)
            evidence_list = self.case_store.get_evidence(case_id)
            for ev in evidence_list:
                events.append(
                    TimelineEvent(
                        investigation_id=investigation_id,
                        event_type="CASE_EVIDENCE",
                        entity_id=ev.evidence_id,
                        description=f"Evidence added: {ev.evidence_type.value} - {ev.description}",
                        timestamp=ev.created_at,
                        metadata={
                            "analyst_id": ev.analyst_id,
                            "evidence_type": ev.evidence_type.value,
                            "description": ev.description,
                            "reference_id": ev.reference_id,
                        }
                    )
                )

            # Get forensic verified evidence (registered in forensics store)
            forensic_evidence = self.forensics_store.list_evidence_for_case(case_id)
            for fe in forensic_evidence:
                events.append(
                    TimelineEvent(
                        investigation_id=investigation_id,
                        event_type="FORENSIC_EVIDENCE",
                        entity_id=fe.id,
                        description=f"Forensic verified evidence registered ({fe.type})",
                        timestamp=fe.created_at,
                        metadata={
                            "evidence_type": fe.type,
                            "source": fe.source,
                            "integrity_hash": fe.hash,
                        }
                    )
                )

        # Sort chronologically by timestamp
        events.sort(key=lambda e: e.timestamp)
        return events

    def add_custom_event(
        self,
        investigation_id: str,
        event_type: str,
        entity_id: str,
        description: str,
        metadata: Dict[str, Any],
    ) -> TimelineEvent:
        """Register a manual or custom timeline event directly for an investigation."""
        event = TimelineEvent(
            investigation_id=investigation_id,
            event_type=event_type,
            entity_id=entity_id,
            description=description,
            metadata=metadata,
        )
        self.forensics_store.add_event(event)
        logger.info(f"Custom timeline event '{event.id}' added to investigation '{investigation_id}'.")
        return event

