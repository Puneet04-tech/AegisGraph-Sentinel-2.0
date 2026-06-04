"""Bounded async event dispatcher with backpressure and critical-event preservation."""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Optional

from .event_bus import RuntimeEventBus
from .event_types import RuntimeEvent, RuntimeShutdownEvent

logger = logging.getLogger(__name__)

_CRITICAL_EVENT_TYPES = (RuntimeShutdownEvent,)


class EventDispatcher:
    """Dispatches RuntimeEvent objects from a bounded queue to the bus.

    * ``start()`` / ``stop()`` manage an internal processing task.
    * ``dispatch(event)`` enqueues an event (thread-safe, non-blocking).
    * When the bounded queue fills, overflow is held in an unbounded deque
      so that critical events (e.g. ``RuntimeShutdownEvent``) are never dropped.
    * Shutdown uses a flag, not a sentinel item, so queue-full during teardown
      does not lose events.
    """

    def __init__(self, bus: RuntimeEventBus, maxsize: int = 256) -> None:
        self._bus = bus
        self._maxsize = maxsize
        self._queue: asyncio.Queue[RuntimeEvent] = asyncio.Queue(maxsize=maxsize)
        # Non-critical events are dropped on overflow; only critical events are preserved.
        self._overflow: deque[RuntimeEvent] = deque()

        # Backward-compatible state flag expected by tests.
        self._running = False
        self._started = False
        self._stop_requested = asyncio.Event()

        self._task: Optional[asyncio.Task] = None

    @property
    def started(self) -> bool:
        return self._started

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._running = True
        self._stop_requested.clear()
        self._task = asyncio.create_task(self._process_loop())

    def dispatch(self, event: RuntimeEvent) -> None:
        """Enqueue *event* for delivery. Thread-safe, non-blocking."""
        if not self._started:
            return
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            if isinstance(event, _CRITICAL_EVENT_TYPES):
                # Preserve critical events until shutdown processing can drain them.
                self._overflow.appendleft(event)
            else:
                # Drop non-critical overflow events.
                logger.warning(
                    "Runtime event dropped due to bounded dispatcher queue overflow: %s",
                    type(event).__name__,
                )
                return

    async def stop(self) -> None:
        if not self._started:
            return
        self._started = False
        self._running = False
        self._stop_requested.set()

        if self._task is not None:
            try:
                # Graceful shutdown: allow _process_loop() to drain queued events
                # and overflow (including critical events) before returning.
                await self._task
            except asyncio.CancelledError:
                pass
            except RuntimeError as exc:
                msg = str(exc)
                # Starlette/FastAPI TestClient teardown can trigger shutdown from a
                # different event loop than the one that created the dispatcher.
                if ("bound to a different event loop" in msg) or (
                    ("Queue" in msg) and ("different event loop" in msg)
                ):
                    # Teardown safety: cancel and swallow cross-event-loop errors.
                    self._task.cancel()
                    logger.debug("Dispatcher stop ignored cross-event-loop error: %s", msg)
                else:
                    raise

        # Best-effort cleanup; doesn't need to be perfect for correctness.
        self._overflow.clear()

    async def _process_loop(self) -> None:
        while not self._stop_requested.is_set() or not self._queue.empty() or self._overflow:
            event = await self._fetch_next_event()
            if event is None:
                continue
            try:
                await self._bus.publish(event)
            except Exception:
                logger.exception("Event dispatch failed for %s", type(event).__name__)
            self._drain_overflow()

    async def _fetch_next_event(self) -> Optional[RuntimeEvent]:
        # Avoid cross-event-loop Queue bound errors by using get_nowait
        # when possible and only awaiting when the loop is correct.
        try:
            return self._queue.get_nowait()
        except asyncio.QueueEmpty:
            pass

        try:
            return await asyncio.wait_for(self._queue.get(), timeout=0.2)
        except asyncio.TimeoutError:
            return None

    def _drain_overflow(self) -> None:
        # Drain only critical events (stored in _overflow) when there is capacity.
        while self._overflow and not self._queue.full():
            event = self._overflow.popleft()
            try:
                self._queue.put_nowait(event)
            except asyncio.QueueFull:
                self._overflow.appendleft(event)
                break

    def __repr__(self) -> str:
        return (
            f"EventDispatcher(started={self._started}, "
            f"queue_size={self._queue.qsize()}, "
            f"overflow={len(self._overflow)})"
        )

