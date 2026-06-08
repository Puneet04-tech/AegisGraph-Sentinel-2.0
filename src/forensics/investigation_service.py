"""Investigation Service managing the lifecycle of digital investigations."""

from __future__ import annotations

import logging
from typing import List, Optional

from .models import Investigation, TimelineEvent
from .store import get_forensics_store
from .timeline_engine import TimelineEngine

logger = logging.getLogger("forensics.investigation_service")


class InvestigationService:
    """Orchestrates creation, case binding, and state transitions for investigations."""

    def __init__(self) -> None:
        self.store = get_forensics_store()
        self.timeline_engine = TimelineEngine()

    def create_investigation(self, title: str, analyst_id: str, case_ids: Optional[List[str]] = None) -> Investigation:
        """Create a new forensic investigation and log the creation event."""
        investigation = Investigation(
            title=title,
            analyst_id=analyst_id,
            case_ids=case_ids or []
        )
        self.store.add_investigation(investigation)
        
        # Log timeline event
        self.timeline_engine.add_custom_event(
            investigation_id=investigation.id,
            event_type="INVESTIGATION_CREATED",
            entity_id=investigation.id,
            description=f"Investigation created by analyst '{analyst_id}' with {len(investigation.case_ids)} linked cases.",
            metadata={"analyst_id": analyst_id, "initial_cases": investigation.case_ids}
        )
        return investigation

    def update_status(self, investigation_id: str, new_status: str, analyst_id: str) -> Optional[Investigation]:
        """Advance the status of an active investigation."""
        investigation = self.store.get_investigation(investigation_id)
        if not investigation:
            return None
            
        old_status = investigation.status
        investigation.status = new_status
        from .models import _utcnow
        investigation.updated_at = _utcnow()
        
        self.timeline_engine.add_custom_event(
            investigation_id=investigation_id,
            event_type="STATUS_CHANGED",
            entity_id=investigation_id,
            description=f"Investigation status changed from '{old_status}' to '{new_status}' by '{analyst_id}'.",
            metadata={"old_status": old_status, "new_status": new_status, "analyst_id": analyst_id}
        )
        return investigation

    def link_cases(self, investigation_id: str, case_ids: List[str], analyst_id: str) -> Optional[Investigation]:
        """Link additional cases to an existing investigation."""
        investigation = self.store.get_investigation(investigation_id)
        if not investigation:
            return None
            
        new_links = []
        for cid in case_ids:
            if cid not in investigation.case_ids:
                investigation.case_ids.append(cid)
                new_links.append(cid)
                
        if new_links:
            from .models import _utcnow
            investigation.updated_at = _utcnow()
            self.timeline_engine.add_custom_event(
                investigation_id=investigation_id,
                event_type="CASES_LINKED",
                entity_id=investigation_id,
                description=f"Linked {len(new_links)} new case(s) to investigation: {', '.join(new_links)}",
                metadata={"linked_cases": new_links, "analyst_id": analyst_id}
            )
        return investigation

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        return self.store.get_investigation(investigation_id)

    def list_investigations(self) -> List[Investigation]:
        return self.store.list_investigations()

