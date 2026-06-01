"""Async background event dispatcher for AegisGraph Sentinel 2.0."""

from __future__ import annotations

import asyncio
import traceback
from typing import Optional

from ...observability import get_logger
from .event_bus import RuntimeEventBus
from .event_types import RuntimeEvent

_logger = get_logger("runtime.events.dispatcher")

_SENTINEL = object()  # signals the dispatch loop to stop


class EventDispatcher:
    """
    Bounded in-memory async dispatcher that decouples event producers
    from the event bus.

    * dispatch(event)  – non-blocking; safe to call from sync or async code.
    * start()          – launches the background processing loop.
    * stop()           – gracefully drains the queue and stops the loop.

    If the queue is full the event is dropped and a warning is logged so
    that a slow consumer never blocks runtime-critical paths.
    """

    def __init__(self, bus: RuntimeEventBus, maxsize: int = 1000) -> None:
        self._bus = bus
        self._maxsize = maxsize
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._task: Optional[asyncio.Task] = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background dispatch loop."""
        if self._running:
            return
        self._running = True
        # Recreate the queue each time start() is called so stale
        # items from a previous run do not leak through.
        self._queue = asyncio.Queue(maxsize=self._maxsize)
        self._task = asyncio.create_task(self._loop(), name="runtime_event_dispatcher")
        _logger.info(
            "Event dispatcher started",
            event_type="event_dispatcher_started",
            metadata={"maxsize": self._maxsize},
        )

    async def stop(self) -> None:
        """
        Gracefully stop the dispatcher.

        Sends a sentinel value so the loop processes all already-queued
        events before exiting.
        """
        if not self._running:
            return
        self._running = False
        try:
            # Put sentinel without blocking; if full, force it by making room.
            self._queue.put_nowait(_SENTINEL)
        except asyncio.QueueFull:
            # Drain one item to make room for the sentinel.
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                self._queue.put_nowait(_SENTINEL)
            except asyncio.QueueFull:
                pass

        if self._task is not None and not self._task.done():
            try:
                await self._task
            except Exception:
                pass
            self._task = None

        _logger.info("Event dispatcher stopped", event_type="event_dispatcher_stopped")

    # ------------------------------------------------------------------
    # Dispatching
    # ------------------------------------------------------------------

    def dispatch(self, event: RuntimeEvent) -> None:
        """
        Enqueue *event* for async processing.  Non-blocking and thread-safe.

        If the queue is at capacity the event is silently dropped after
        logging a warning – this guarantees that runtime-critical code
        paths are never blocked.
        """
        if not self._running:
            # Dispatcher not yet started or already stopped – ignore.
            return

        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            _logger.warning(
                f"Event dispatcher queue is full (maxsize={self._maxsize}); "
                f"dropping event {type(event).__name__} (id={event.event_id})",
                event_type="event_dispatcher_queue_full",
                metadata={
                    "event_type": type(event).__name__,
                    "event_id": event.event_id,
                    "source": event.source,
                },
            )

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        """Background dispatch loop – runs until a sentinel is received."""
        _logger.info("Event dispatcher loop running", event_type="event_dispatcher_loop_started")
        try:
            while True:
                item = await self._queue.get()
                if item is _SENTINEL:
                    # Drain any remaining real events before exiting.
                    while not self._queue.empty():
                        remaining = self._queue.get_nowait()
                        if remaining is not _SENTINEL:
                            await self._publish_safe(remaining)
                    self._queue.task_done()
                    break
                await self._publish_safe(item)
                self._queue.task_done()
        except asyncio.CancelledError:
            _logger.info(
                "Event dispatcher loop cancelled",
                event_type="event_dispatcher_loop_cancelled",
            )
            raise
        except Exception as exc:
            _logger.error(
                f"Event dispatcher loop crashed: {exc}",
                event_type="event_dispatcher_loop_crashed",
                metadata={
                    "error": str(exc),
                    "traceback": "".join(
                        traceback.format_exception(type(exc), exc, exc.__traceback__)
                    ),
                },
            )

    async def _publish_safe(self, event: RuntimeEvent) -> None:
        """Publish a single event through the bus with isolated error handling."""
        try:
            await self._bus.publish(event)
        except Exception as exc:
            _logger.error(
                f"Event dispatcher failed to publish {type(event).__name__}: {exc}",
                event_type="event_dispatcher_publish_error",
                metadata={
                    "event_type": type(event).__name__,
                    "event_id": event.event_id,
                    "error": str(exc),
                },
            )
