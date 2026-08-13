import pytest
import asyncio

from src.api.websocket_manager import WebSocketManager


class MockWebSocket:
    def __init__(self):
        self.accepted = False
        self.closed = False
        self.close_code = None
        self.messages = []

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000, reason=""):
        self.closed = True
        self.close_code = code

    async def send_json(self, data):
        if self.closed:
            raise Exception("Cannot send on closed connection")

        self.messages.append(data)


@pytest.mark.anyio
async def test_websocket_connect_and_disconnect():
    manager = WebSocketManager()
    ws = MockWebSocket()

    accepted = await manager.connect(ws, "client_1")

    assert accepted is True
    assert ws.accepted is True
    assert "client_1" in manager.active_connections

    await manager.disconnect("client_1")

    assert "client_1" not in manager.active_connections


@pytest.mark.anyio
async def test_reconnect_backoff():
    manager = WebSocketManager(max_reconnect_attempts=3)
    ws = MockWebSocket()

    for _ in range(3):
        assert await manager.connect(ws, "flood_client") is True
        await manager.disconnect("flood_client")

    ws_rejected = MockWebSocket()

    accepted = await manager.connect(ws_rejected, "flood_client")

    assert accepted is False
    assert ws_rejected.closed is True
    assert ws_rejected.close_code == 1008


@pytest.mark.anyio
async def test_heartbeat_and_stale_cleanup():
    manager = WebSocketManager(heartbeat_timeout=0.1)

    ws1 = MockWebSocket()
    ws2 = MockWebSocket()

    await manager.connect(ws1, "active_client")
    await manager.connect(ws2, "stale_client")

    await asyncio.sleep(0.15)

    await manager.heartbeat("active_client")

    await manager.cleanup_stale_connections()

    assert "active_client" in manager.active_connections
    assert "stale_client" not in manager.active_connections
    assert ws2.closed is True


@pytest.mark.anyio
async def test_broadcast():
    manager = WebSocketManager()

    ws1 = MockWebSocket()
    ws2 = MockWebSocket()

    await manager.connect(ws1, "client_1")
    await manager.connect(ws2, "client_2")

    await manager.broadcast({"fraud_alert": "high"})

    assert len(ws1.messages) == 1
    assert ws1.messages[0] == {"fraud_alert": "high"}

    assert len(ws2.messages) == 1
    assert ws2.messages[0] == {"fraud_alert": "high"}


@pytest.mark.anyio
async def test_connection_replacement_closes_previous_socket():
    manager = WebSocketManager()
    ws1 = MockWebSocket()
    ws2 = MockWebSocket()

    await manager.connect(ws1, "client_replacement")
    assert manager.active_connections["client_replacement"].websocket is ws1

    await manager.connect(ws2, "client_replacement")
    assert manager.active_connections["client_replacement"].websocket is ws2
    assert ws1.closed is True
    assert ws1.close_code == 1000
    assert ws2.closed is False


@pytest.mark.anyio
async def test_lock_not_held_during_close():
    manager = WebSocketManager()

    class SlowCloseWebSocket(MockWebSocket):
        async def close(self, code=1000, reason=""):
            self.closed = True
            await asyncio.sleep(0.5)

    ws_slow = SlowCloseWebSocket()
    ws_new = MockWebSocket()
    ws_other = MockWebSocket()

    await manager.connect(ws_slow, "slow_client")
    await manager.connect(ws_other, "other_client")

    reconnect_task = asyncio.create_task(manager.connect(ws_new, "slow_client"))
    await asyncio.sleep(0.05)

    # Invoke heartbeat on another client while reconnect is waiting in slow_close()
    start_time = asyncio.get_event_loop().time()
    await manager.heartbeat("other_client")
    elapsed = asyncio.get_event_loop().time() - start_time

    # Heartbeat must execute immediately (<0.4s) and not block for slow_close (0.5s)
    assert elapsed < 0.4
    await reconnect_task



@pytest.mark.anyio
async def test_close_exception_handling():
    manager = WebSocketManager()

    class ErrorWebSocket(MockWebSocket):
        async def close(self, code=1000, reason=""):
            raise RuntimeError("Network socket closed forcibly by peer")

    ws_err = ErrorWebSocket()
    ws_new = MockWebSocket()

    await manager.connect(ws_err, "err_client")

    # Reconnecting should swallow the close exception and set active connection
    res = await manager.connect(ws_new, "err_client")
    assert res is True
    assert manager.active_connections["err_client"].websocket is ws_new

    # Subsequent operations should continue working
    await manager.heartbeat("err_client")
    assert manager.active_connections["err_client"].last_heartbeat > 0


@pytest.mark.anyio
async def test_multiple_rapid_reconnects():
    manager = WebSocketManager()
    sockets = [MockWebSocket() for _ in range(5)]

    for ws in sockets:
        await manager.connect(ws, "rapid_client")

    assert manager.active_connections["rapid_client"].websocket is sockets[-1]
    for ws in sockets[:-1]:
        assert ws.closed is True
    assert sockets[-1].closed is False


@pytest.mark.anyio
async def test_stale_cleanup_does_not_evict_reconnected_client_during_close():
    """Verify that stale cleanup passing a socket reference does not delete a reconnected client."""
    manager = WebSocketManager(heartbeat_timeout=0.1)

    class ControlledCloseMockWebSocket(MockWebSocket):
        def __init__(self):
            super().__init__()
            self.close_started = asyncio.Event()
            self.close_resume = asyncio.Event()

        async def close(self, code=1000, reason=""):
            self.closed = True
            self.close_code = code
            if not self.close_started.is_set():
                self.close_started.set()
                await self.close_resume.wait()

    ws_old = ControlledCloseMockWebSocket()
    await manager.connect(ws_old, "client_race")

    # Manually backdate the heartbeat to force stale status
    manager.active_connections["client_race"].last_heartbeat -= 1.0

    # Launch stale cleanup in the background
    cleanup_task = asyncio.create_task(manager.cleanup_stale_connections())

    # Wait until stale cleanup enters ws_old.close()
    await ws_old.close_started.wait()

    # Reconnect the client while stale cleanup is suspended in ws_old.close()
    ws_new = MockWebSocket()
    reconnect_success = await manager.connect(ws_new, "client_race")
    assert reconnect_success is True
    assert manager.active_connections["client_race"].websocket is ws_new

    # Resume ws_old.close() to let cleanup_stale_connections finish
    ws_old.close_resume.set()
    await cleanup_task

    # The reconnected websocket must still be active and not deleted
    assert "client_race" in manager.active_connections
    assert manager.active_connections["client_race"].websocket is ws_new
    assert ws_new.closed is False
    assert ws_old.closed is True
    assert ws_old.close_code == 1000


@pytest.mark.anyio
async def test_stale_cleanup_ignores_client_reconnected_before_close_loop():
    """Verify stale cleanup skips clients that reconnected before close iteration."""
    manager = WebSocketManager(heartbeat_timeout=0.1)

    ws_old = MockWebSocket()
    await manager.connect(ws_old, "client_early")

    # Backdate heartbeat
    manager.active_connections["client_early"].last_heartbeat -= 1.0

    # Reconnect happens before cleanup_stale_connections runs
    ws_new = MockWebSocket()
    await manager.connect(ws_new, "client_early")

    await manager.cleanup_stale_connections()

    # New socket remains active
    assert "client_early" in manager.active_connections
    assert manager.active_connections["client_early"].websocket is ws_new
    assert ws_new.closed is False


@pytest.mark.anyio
async def test_stale_cleanup_removes_unreconnected_stale_client_normally():
    """Verify standard stale connection cleanup without reconnect removes client."""
    manager = WebSocketManager(heartbeat_timeout=0.1)

    ws_stale = MockWebSocket()
    await manager.connect(ws_stale, "client_normal")

    manager.active_connections["client_normal"].last_heartbeat -= 1.0

    await manager.cleanup_stale_connections()

    assert "client_normal" not in manager.active_connections
    assert ws_stale.closed is True


