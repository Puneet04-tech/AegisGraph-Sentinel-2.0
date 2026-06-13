"""Timeline Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import Timeline, TimelineEvent, EventType

class TimelineService:
    """Investigation Timeline Service"""
    
    def __init__(self) -> None:
        self.timelines: Dict[str, Timeline] = {}
        self.events: Dict[str, TimelineEvent] = {}
    
    def create_timeline(self, investigation_id: str, name: str) -> Dict[str, Any]:
        """Create a timeline"""
        timeline = Timeline(
            timeline_id=str(uuid4())[:8],
            investigation_id=investigation_id,
            name=name
        )
        self.timelines[timeline.timeline_id] = timeline
        return timeline.to_dict()
    
    def add_event(
        self,
        investigation_id: str,
        event_type: str,
        title: str,
        description: str,
        source: str,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Add an event to a timeline"""
        event = TimelineEvent(
            event_id=str(uuid4())[:8],
            investigation_id=investigation_id,
            event_type=EventType(event_type),
            timestamp=timestamp or datetime.utcnow(),
            title=title,
            description=description,
            source=source,
            metadata=metadata or {}
        )
        self.events[event.event_id] = event
        
        # Add to timeline
        for timeline in self.timelines.values():
            if timeline.investigation_id == investigation_id:
                timeline.events.append(event.event_id)
        
        return event.to_dict()
    
    def get_timeline(self, timeline_id: str) -> Optional[Dict[str, Any]]:
        """Get a timeline"""
        timeline = self.timelines.get(timeline_id)
        return timeline.to_dict() if timeline else None
    
    def get_timeline_events(self, timeline_id: str) -> List[Dict[str, Any]]:
        """Get events for a timeline"""
        timeline = self.timelines.get(timeline_id)
        if not timeline:
            return []
        events = [self.events.get(eid) for eid in timeline.events if self.events.get(eid)]
        events.sort(key=lambda e: e.timestamp)
        return [e.to_dict() for e in events]
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get timeline dashboard"""
        type_counts: Dict[str, int] = {}
        for event in self.events.values():
            type_counts[event.event_type.value] = type_counts.get(event.event_type.value, 0) + 1
        
        return {
            "total_timelines": len(self.timelines),
            "total_events": len(self.events),
            "events_by_type": type_counts
        }


_timeline_service: Optional[TimelineService] = None

def get_timeline_service() -> TimelineService:
    """Get the global service instance"""
    global _timeline_service
    if _timeline_service is None:
        _timeline_service = TimelineService()
    return _timeline_service