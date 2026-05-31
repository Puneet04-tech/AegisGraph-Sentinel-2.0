import pytest
import time

from src.api.websocket_manager import WebSocketManager


@pytest.mark.asyncio
async def test_disconnect_history_eviction_drops_stale_clients():
    manager = WebSocketManager(disconnect_history_ttl=1.0, max_disconnect_history_entries=10)
    now = time.time()
    manager.disconnect_history = {
        "stale-client": [now - 10.0, now - 9.0],
        "fresh-client": [now - 0.2],
    }

    await manager.evict_stale_disconnect_history()

    assert "stale-client" not in manager.disconnect_history
    assert "fresh-client" in manager.disconnect_history


@pytest.mark.asyncio
async def test_disconnect_history_eviction_caps_total_clients():
    manager = WebSocketManager(disconnect_history_ttl=60.0, max_disconnect_history_entries=2)
    now = time.time()
    manager.disconnect_history = {
        "client-a": [now - 30.0],
        "client-b": [now - 20.0],
        "client-c": [now - 10.0],
    }

    await manager.evict_stale_disconnect_history()

    assert len(manager.disconnect_history) == 2
    assert "client-a" not in manager.disconnect_history
