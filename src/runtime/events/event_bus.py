"""Lightweight async-safe runtime event bus for AegisGraph Sentinel 2.0."""

from __future__ import annotations

import asyncio
import traceback
from collections import defaultdict
from typing import Any, Callable, Dict, List, Type

from ...observability import get_logger
from .event_types import RuntimeEvent

_logger = get_logger("runtime.events.bus")

AsyncHandler = Callable[[RuntimeEvent], Any]


class RuntimeEventBus:
    """
    Lightweight in-process async event bus.

    * subscribe(event_type, handler)  – register a sync or async handler
    * unsubscribe(event_type, handler) – deregister a handler
    * publish(event)                  – invoke all matching handlers, isolated

    Handler failure isolation guarantee: one failing handler never prevents
    other handlers or the publisher from continuing.
    """

    def __init__(self) -> None:
        # Maps event_type class → list of registered handlers
        self._handlers: Dict[Type[RuntimeEvent], List[AsyncHandler]] = defaultdict(list)
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------

    async def subscribe(self, event_type: Type[RuntimeEvent], handler: AsyncHandler) -> None:
        """Register *handler* to receive events of *event_type* (and subclasses)."""
        async with self._lock:
            if handler not in self._handlers[event_type]:
                self._handlers[event_type].append(handler)

    async def unsubscribe(self, event_type: Type[RuntimeEvent], handler: AsyncHandler) -> None:
        """Deregister *handler* for *event_type*."""
        async with self._lock:
            handlers = self._handlers.get(event_type)
            if handlers and handler in handlers:
                handlers.remove(handler)

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    async def publish(self, event: RuntimeEvent) -> None:
        """
        Dispatch *event* to all handlers whose registered type matches
        the concrete event class or any of its base classes.

        Each handler is executed in isolation – exceptions are logged
        but never propagated to the caller or to sibling handlers.
        """
        async with self._lock:
            # Collect all handlers whose key is a superclass-or-equal of the event type
            matched: List[AsyncHandler] = []
            for registered_type, handlers in self._handlers.items():
                if isinstance(event, registered_type):
                    matched.extend(handlers)

        if not matched:
            return

        for handler in matched:
            await self._invoke_handler(handler, event)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _invoke_handler(self, handler: AsyncHandler, event: RuntimeEvent) -> None:
        """Execute a single handler with full failure isolation."""
        try:
            result = handler(event)
            if asyncio.iscoroutine(result):
                await result
        except Exception as exc:
            _logger.error(
                f"Event handler raised an exception (handler: {handler!r}, "
                f"event: {type(event).__name__}, event_id: {event.event_id}): {exc}",
                event_type="event_bus_handler_error",
                metadata={
                    "handler": repr(handler),
                    "event_type": type(event).__name__,
                    "event_id": event.event_id,
                    "error": str(exc),
                    "traceback": "".join(
                        traceback.format_exception(type(exc), exc, exc.__traceback__)
                    ),
                },
            )
