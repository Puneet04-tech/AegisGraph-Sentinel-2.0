"""Tests that Redis pool shutdown actually closes pools and reports failures.

Both loops previously ended in ``except Exception: pass``, and the async
branch called ``.close()`` on the disconnect coroutine -- cancelling it rather
than running it, so async pools were never disconnected at all.
"""

import asyncio

import pytest

from src.utils import redis_client


class SyncPool:
    def __init__(self, error=None):
        self.error = error
        self.disconnected = False

    def disconnect(self):
        if self.error:
            raise self.error
        self.disconnected = True


class AsyncPool:
    """Mirrors redis.asyncio: disconnect() returns a coroutine."""

    def __init__(self, error=None):
        self.error = error
        self.disconnected = False

    def disconnect(self):
        return self._disconnect()

    async def _disconnect(self):
        if self.error:
            raise self.error
        self.disconnected = True


@pytest.fixture(autouse=True)
def clean_pools():
    redis_client._redis_pools.clear()
    redis_client._async_redis_pools.clear()
    yield
    redis_client._redis_pools.clear()
    redis_client._async_redis_pools.clear()


class TestSyncPoolShutdown:
    def test_pools_are_disconnected_and_cleared(self):
        pool = SyncPool()
        redis_client._redis_pools["redis://a"] = pool

        redis_client.close_redis_pools()

        assert pool.disconnected is True
        assert redis_client._redis_pools == {}

    def test_failure_is_logged_not_swallowed(self, caplog):
        redis_client._redis_pools["redis://a"] = SyncPool(RuntimeError("boom"))

        with caplog.at_level("WARNING"):
            redis_client.close_redis_pools()

        assert "may leak" in caplog.text

    def test_one_failure_does_not_strand_the_other_pools(self):
        healthy = SyncPool()
        redis_client._redis_pools["redis://bad"] = SyncPool(RuntimeError("boom"))
        redis_client._redis_pools["redis://good"] = healthy

        redis_client.close_redis_pools()

        assert healthy.disconnected is True
        assert redis_client._redis_pools == {}


class TestAsyncPoolShutdownFromSync:
    def test_async_pool_is_actually_disconnected(self):
        pool = AsyncPool()
        redis_client._async_redis_pools["redis://a"] = pool

        redis_client.close_redis_pools()

        # The old code cancelled this coroutine instead of running it, so the
        # pool stayed connected while appearing closed.
        assert pool.disconnected is True
        assert redis_client._async_redis_pools == {}

    def test_async_disconnect_failure_is_logged(self, caplog):
        redis_client._async_redis_pools["redis://a"] = AsyncPool(RuntimeError("boom"))

        with caplog.at_level("WARNING"):
            redis_client.close_redis_pools()

        assert "may leak" in caplog.text

    def test_running_loop_is_reported_rather_than_silently_leaking(self, caplog):
        pool = AsyncPool()
        redis_client._async_redis_pools["redis://a"] = pool

        async def close_from_inside_a_loop():
            redis_client.close_redis_pools()

        with caplog.at_level("WARNING"):
            asyncio.run(close_from_inside_a_loop())

        assert pool.disconnected is False
        assert "NOT disconnected" in caplog.text


class TestAsyncPoolShutdown:
    def test_await_path_disconnects(self):
        pool = AsyncPool()
        redis_client._async_redis_pools["redis://a"] = pool

        asyncio.run(redis_client.close_async_redis_pools())

        assert pool.disconnected is True
        assert redis_client._async_redis_pools == {}

    def test_failure_is_logged(self, caplog):
        redis_client._async_redis_pools["redis://a"] = AsyncPool(RuntimeError("boom"))

        with caplog.at_level("WARNING"):
            asyncio.run(redis_client.close_async_redis_pools())

        assert "may leak" in caplog.text

    def test_one_failure_does_not_strand_the_others(self):
        healthy = AsyncPool()
        redis_client._async_redis_pools["redis://bad"] = AsyncPool(RuntimeError("boom"))
        redis_client._async_redis_pools["redis://good"] = healthy

        asyncio.run(redis_client.close_async_redis_pools())

        assert healthy.disconnected is True
