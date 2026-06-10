"""
Event Bus Module.

Event-driven architecture with pub/sub and event routing.
"""

import random
import threading
from threading import Lock
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timezone
import logging

from .models import (
    StreamEvent,
    StreamSubscription,
    EventPriority,
)
from .store import StreamStore, get_stream_store

logger = logging.getLogger(__name__)


class EventBus:
    """Event Bus for pub/sub and event routing.
    
    Provides:
        - Event publishing
        - Event subscription
        - Event routing
        - Event filtering
    """
    
    def __init__(self, store: Optional[StreamStore] = None):
        """Initialize the event bus."""
        self._store = store or get_stream_store()
        self._module_id = "event_bus"
        self._subscribers: Dict[str, List[Callable]] = {}
        self._event_history: List[StreamEvent] = []
    
    def publish_event(
        self,
        event_type: str,
        source: str,
        payload: Dict[str, Any],
        priority: EventPriority = EventPriority.MEDIUM,
    ) -> StreamEvent:
        """Publish an event to the bus."""
        logger.info(f"Publishing event: {event_type}")
        
        event = StreamEvent(
            event_type=event_type,
            source=source,
            payload=payload,
            priority=priority,
        )
        
        # Store in history
        self._event_history.append(event)
        if len(self._event_history) > 1000:
            self._event_history = self._event_history[-1000:]
        
        # Notify subscribers
        self._notify_subscribers(event)
        
        return event
    
    def subscribe(
        self,
        stream_name: str,
        subscriber_id: str,
        filter_criteria: Dict[str, Any] = None,
    ) -> StreamSubscription:
        """Subscribe to events."""
        logger.info(f"Subscribing {subscriber_id} to {stream_name}")
        
        subscription = StreamSubscription(
            stream_name=stream_name,
            subscriber_id=subscriber_id,
            filter_criteria=filter_criteria or {},
        )
        
        self._store.store_subscription(subscription)
        return subscription
    
    def add_subscriber_handler(
        self,
        event_type: str,
        handler: Callable,
    ) -> None:
        """Add a subscriber handler for an event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)
    
    def _notify_subscribers(self, event: StreamEvent) -> None:
        """Notify subscribers of an event."""
        # Get matching subscriptions
        subscriptions = self._store.get_subscriptions(event.event_type)
        
        for subscription in subscriptions:
            # Check filter criteria
            if self._matches_filter(event, subscription.filter_criteria):
                handlers = self._subscribers.get(event.event_type, [])
                for handler in handlers:
                    try:
                        handler(event, subscription.subscriber_id)
                    except Exception as e:
                        logger.error(f"Subscriber handler error: {e}")
    
    def _matches_filter(
        self,
        event: StreamEvent,
        filter_criteria: Dict[str, Any],
    ) -> bool:
        """Check if event matches filter criteria."""
        if not filter_criteria:
            return True
        
        # Check event_type
        if "event_type" in filter_criteria:
            if event.event_type != filter_criteria["event_type"]:
                return False
        
        # Check priority
        if "priority" in filter_criteria:
            if event.priority.value != filter_criteria["priority"]:
                return False
        
        # Check payload fields
        if "payload_fields" in filter_criteria:
            for field, expected in filter_criteria["payload_fields"].items():
                if event.payload.get(field) != expected:
                    return False
        
        return True
    
    def route_event(
        self,
        event: StreamEvent,
        routes: List[Dict[str, Any]],
    ) -> List[str]:
        """Route an event based on rules."""
        logger.info(f"Routing event: {event.event_id}")
        
        matched_routes = []
        
        for route in routes:
            if self._matches_route(event, route):
                matched_routes.append(route["destination"])
                logger.info(f"Event routed to {route['destination']}")
        
        return matched_routes
    
    def _matches_route(
        self,
        event: StreamEvent,
        route: Dict[str, Any],
    ) -> bool:
        """Check if event matches a route."""
        route_type = route.get("type", "event_type")
        
        if route_type == "event_type":
            return event.event_type == route.get("event_type")
        elif route_type == "priority":
            return event.priority.value == route.get("priority")
        elif route_type == "pattern":
            # Check payload pattern
            pattern = route.get("pattern", {})
            for key, expected in pattern.items():
                if event.payload.get(key) != expected:
                    return False
            return True
        
        return False
    
    def get_event_history(
        self,
        event_type: str = None,
        limit: int = 100,
    ) -> List[StreamEvent]:
        """Get event history."""
        events = self._event_history
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        return events[-limit:]
    
    def correlate_events(
        self,
        event_ids: List[str],
    ) -> Dict[str, Any]:
        """Correlate multiple events."""
        events = [
            e for e in self._event_history
            if e.event_id in event_ids
        ]
        
        if len(events) < 2:
            return {"correlation_id": None, "events": [], "relationship": "insufficient"}
        
        # Analyze correlation
        timestamps = [e.timestamp for e in events]
        sources = set(e.source for e in events)
        priorities = [e.priority.value for e in events]
        
        # Determine relationship
        if len(sources) == 1:
            relationship = "same_source"
        elif all(p == priorities[0] for p in priorities):
            relationship = "same_priority"
        else:
            relationship = "related"
        
        return {
            "correlation_id": f"corr_{events[0].event_id[:8]}",
            "event_count": len(events),
            "sources": list(sources),
            "relationship": relationship,
            "time_span_seconds": (
                max(timestamps) - min(timestamps)
            ).total_seconds(),
        }


# Global singleton
_event_bus: Optional[EventBus] = None
_event_bus_lock = Lock()


def get_event_bus(store: Optional[StreamStore] = None) -> EventBus:
    """Get or create the singleton EventBus instance."""
    global _event_bus
    
    with _event_bus_lock:
        if _event_bus is None:
            _event_bus = EventBus(store=store)
        return _event_bus