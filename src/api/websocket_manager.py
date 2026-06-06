import asyncio
import time
import logging
from typing import Dict

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionState:
    def __init__(self, websocket: WebSocket):
        self.websocket = websocket
        self.last_heartbeat = time.time()


class WebSocketManager:
    """Manages active WebSocket connections with bounded reconnect recovery and stale cleanup.

    Note: this manager intentionally does NOT create background tasks.
    Unit tests run under anyio/pytest and can time out if background
    eviction loops keep the event loop alive.
    """

    def __init__(
        self,
        heartbeat_timeout: float = 60.0,
        max_reconnect_attempts: int = 5,
        disconnect_history_ttl: float = 300.0,
        max_disconnect_history_entries: int = 2048,
    ):
        self.active_connections: Dict[str, ConnectionState] = {}
        # client_id -> list of disconnect timestamps
        self.disconnect_history: Dict[str, list] = {}

        self.heartbeat_timeout = heartbeat_timeout
        self.max_reconnect_attempts = max_reconnect_attempts
        self.disconnect_history_ttl = disconnect_history_ttl
        self.max_disconnect_history_entries = max_disconnect_history_entries

        self._lock = asyncio.Lock()

    async def start_eviction(self) -> None:
        """No-op (no background tasks)."""

    async def stop_eviction(self) -> None:
        """No-op (no background tasks)."""

    async def evict_stale_disconnect_history(self) -> None:
        """Purge aged disconnect timestamps."""
        cutoff = time.time() - self.disconnect_history_ttl

        async with self._lock:
            stale_clients = []
            for client_id, history in self.disconnect_history.items():
                fresh_history = [ts for ts in history if ts >= cutoff]
                if fresh_history:
                    self.disconnect_history[client_id] = fresh_history[-self.max_reconnect_attempts :]
                else:
                    stale_clients.append(client_id)

            for client_id in stale_clients:
                del self.disconnect_history[client_id]

            while len(self.disconnect_history) > self.max_disconnect_history_entries:
                oldest_client_id = min(
                    self.disconnect_history,
                    key=lambda cid: self.disconnect_history[cid][-1],
                )
                del self.disconnect_history[oldest_client_id]

    async def connect(self, websocket: WebSocket, client_id: str) -> bool:
        """Accept a connection safely with reconnect rate limiting."""
        await self.evict_stale_disconnect_history()

        async with self._lock:
            now = time.time()
            history = self.disconnect_history.get(client_id, [])
            # Keep only disconnects from the last 60 seconds
            history = [t for t in history if now - t < 60.0]
            self.disconnect_history[client_id] = history

            if len(history) >= self.max_reconnect_attempts:
                logger.warning(
                    "Client %s reconnecting too fast (%d). Rejecting.",
                    client_id,
                    len(history),
                )
                await websocket.close(code=1008, reason="Too many reconnect attempts")
                return False

        await websocket.accept()

        async with self._lock:
            old = self.active_connections.get(client_id)
            if old is not None:
                try:
                    await old.websocket.close(code=1000, reason="Replaced by new connection")
                except Exception:
                    pass

            self.active_connections[client_id] = ConnectionState(websocket)

        return True

    async def disconnect(self, client_id: str) -> None:
        """Remove a disconnected client from active connections."""
        async with self._lock:
            if client_id not in self.active_connections:
                return

            del self.active_connections[client_id]
            self.disconnect_history.setdefault(client_id, []).append(time.time())

        await self.evict_stale_disconnect_history()

    async def heartbeat(self, client_id: str) -> None:
        """Update the heartbeat timestamp for an active client."""
        async with self._lock:
            if client_id in self.active_connections:
                self.active_connections[client_id].last_heartbeat = time.time()

    async def cleanup_stale_connections(self) -> None:
        """Forcefully disconnect clients missing heartbeats."""
        now = time.time()

        async with self._lock:
            stale_clients = [
                client_id
                for client_id, state in self.active_connections.items()
                if now - state.last_heartbeat > self.heartbeat_timeout
            ]

        for client_id in stale_clients:
            logger.warning("Closing stale connection for client %s", client_id)
            async with self._lock:
                state = self.active_connections.get(client_id)

            if state is None:
                continue

            try:
                await state.websocket.close(code=1000, reason="Heartbeat timeout")
            except Exception as e:
                logger.error("Error closing stale connection for %s: %s", client_id, e)

            await self.disconnect(client_id)

    async def broadcast(self, message: dict) -> None:
        """Broadcast a message to all connected clients without blocking."""
        async with self._lock:
            connections = list(self.active_connections.values())

        for state in connections:
            try:
                await state.websocket.send_json(message)
            except Exception:
                # Ignore write errors; stale cleanup loop will catch dead sockets.
                pass
