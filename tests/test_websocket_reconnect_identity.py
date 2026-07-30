"""A reconnect must not be torn down by the connection it replaced.

``connect`` replaces the entry for a client_id and closes the old socket. The
old handler then unwinds and calls ``disconnect``, which without the socket to
compare against removes the entry that replaced it. The new socket stays open
but is no longer in ``active_connections``, so it silently receives nothing.
"""

import asyncio
import ast
import io

import pytest

from src.api.websocket_manager import WebSocketManager

ROUTE_MODULE = "src/api/main.py"


class FakeWebSocket:
    def __init__(self, name):
        self.name = name
        self.sent = []
        self.closed_with = None

    async def accept(self):
        return None

    async def close(self, code=1000, reason=""):
        self.closed_with = (code, reason)

    async def send_json(self, message):
        self.sent.append(message)


def _run(coroutine):
    return asyncio.run(coroutine)


async def _reconnected_manager():
    manager = WebSocketManager()
    first, second = FakeWebSocket("first"), FakeWebSocket("second")
    await manager.connect(first, "client-1")
    await manager.connect(second, "client-1")
    return manager, first, second


def test_the_replaced_handler_does_not_evict_the_live_connection():
    async def scenario():
        manager, first, second = await _reconnected_manager()

        await manager.disconnect("client-1", first)

        return manager, second

    manager, second = _run(scenario())

    assert "client-1" in manager.active_connections, (
        "the previous connection's cleanup removed the reconnected client, "
        "whose socket is still open"
    )
    assert manager.active_connections["client-1"].websocket is second


def test_the_reconnected_client_still_receives_broadcasts():
    async def scenario():
        manager, first, second = await _reconnected_manager()
        await manager.disconnect("client-1", first)
        await manager.broadcast({"event": "fraud_decision"})
        return first, second

    first, second = _run(scenario())

    assert second.sent == [{"event": "fraud_decision"}]
    assert first.sent == []


def test_the_live_connection_can_still_disconnect_itself():
    async def scenario():
        manager, first, second = await _reconnected_manager()
        await manager.disconnect("client-1", first)
        await manager.disconnect("client-1", second)
        return manager

    manager = _run(scenario())

    assert manager.active_connections == {}


def test_a_superseded_disconnect_still_counts_toward_reconnect_limiting():
    """Dropping the eviction must not also drop the rate limiting signal."""
    async def scenario():
        manager, first, _ = await _reconnected_manager()
        await manager.disconnect("client-1", first)
        return manager

    manager = _run(scenario())

    assert manager.disconnect_history.get("client-1"), (
        "a superseded disconnect recorded nothing, so a client could reconnect "
        "without limit"
    )


def test_disconnect_without_a_socket_still_removes_the_client():
    """The websocket argument is optional, so existing callers keep working."""
    async def scenario():
        manager = WebSocketManager()
        await manager.connect(FakeWebSocket("only"), "client-1")
        await manager.disconnect("client-1")
        return manager

    manager = _run(scenario())

    assert manager.active_connections == {}


def test_disconnecting_an_unknown_client_is_a_no_op():
    async def scenario():
        manager = WebSocketManager()
        await manager.disconnect("never-connected", FakeWebSocket("ghost"))
        return manager

    manager = _run(scenario())

    assert manager.active_connections == {}
    assert manager.disconnect_history == {}


def test_the_websocket_route_identifies_the_socket_it_is_cleaning_up():
    """The manager can only tell connections apart if the caller names one.

    ``disconnect`` still accepts a bare client_id for compatibility, so a route
    that drops the argument reintroduces the defect silently. This reads the
    call site rather than the behaviour, because that is where it would regress.
    """
    tree = ast.parse(io.open(ROUTE_MODULE, encoding="utf-8").read())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "disconnect"
        and getattr(node.func.value, "id", "") == "ws_manager"
    ]

    assert calls, f"{ROUTE_MODULE} never calls ws_manager.disconnect"

    bare = [node.lineno for node in calls if len(node.args) + len(node.keywords) < 2]

    assert not bare, (
        f"{ROUTE_MODULE} calls ws_manager.disconnect without naming the socket "
        f"at line(s) {bare}. After a reconnect that removes the connection that "
        "replaced this one."
    )


@pytest.mark.parametrize("attempts", [3])
def test_repeated_reconnects_keep_only_the_newest(attempts):
    async def scenario():
        manager = WebSocketManager()
        sockets = [FakeWebSocket(f"ws{i}") for i in range(attempts)]
        for socket in sockets:
            await manager.connect(socket, "client-1")
        for socket in sockets[:-1]:
            await manager.disconnect("client-1", socket)
        return manager, sockets[-1]

    manager, newest = _run(scenario())

    assert manager.active_connections["client-1"].websocket is newest
