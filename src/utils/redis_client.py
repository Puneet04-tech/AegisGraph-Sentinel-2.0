import asyncio
import inspect
import logging
import threading
from typing import Dict, Optional

import redis
import redis.asyncio as async_redis

from src.config.settings import get_settings

from ..runtime.failure_policy import should_fail_fast

logger = logging.getLogger(__name__)

_redis_pools: Dict[str, redis.ConnectionPool] = {}
_async_redis_pools: Dict[str, async_redis.ConnectionPool] = {}
_redis_pool: Optional[redis.ConnectionPool] = None
_redis_lock = threading.Lock()


def _build_pool_kwargs(settings) -> dict:
    database = settings.database
    kwargs = {
        "decode_responses": True,
        "max_connections": database.redis_max_connections,
    }
    if database.redis_socket_timeout is not None:
        kwargs["socket_timeout"] = database.redis_socket_timeout
    if database.redis_socket_connect_timeout is not None:
        kwargs["socket_connect_timeout"] = database.redis_socket_connect_timeout
    if database.redis_retry_on_timeout is not None:
        kwargs["retry_on_timeout"] = database.redis_retry_on_timeout
    if database.redis_health_check_interval is not None:
        kwargs["health_check_interval"] = database.redis_health_check_interval
    if database.redis_socket_keepalive is not None:
        kwargs["socket_keepalive"] = database.redis_socket_keepalive
    return kwargs


def get_redis_client(redis_url: Optional[str] = None) -> Optional[redis.Redis]:
    """Get or create Redis client using connection pools keyed by redis_url.

    Provides thread-safe access to Redis connections.
    """
    global _redis_pool
    settings = get_settings()
    database = settings.database
    if redis_url is None:
        redis_url = database.redis_url
    if redis_url is None:
        redis_url = "redis://localhost:6379/0"

    with _redis_lock:
        if redis_url not in _redis_pools:
            try:
                pool = redis.ConnectionPool.from_url(
                    redis_url,
                    **_build_pool_kwargs(settings),
                )
                _redis_pools[redis_url] = pool
                _redis_pool = pool
                logger.info("Created new Redis connection pool for %s", redis_url)
            except Exception as e:
                failure_mode = get_settings().runtime.failure_mode
                logger.error(
                    "Failed to initialize Redis connection pool for %s: %s. runtime.failure_mode=%s",
                    redis_url,
                    e,
                    failure_mode,
                )
                if should_fail_fast(failure_mode):
                    raise
                logger.warning("Continuing without Redis connection pool.")
                return None
        else:
            pool = _redis_pools[redis_url]
            _redis_pool = pool

    return redis.Redis(connection_pool=pool)


def get_async_redis_client(redis_url: Optional[str] = None) -> Optional[async_redis.Redis]:
    """Get or create an async Redis client using connection pools keyed by redis_url."""
    settings = get_settings()
    database = settings.database
    if redis_url is None:
        redis_url = database.redis_url
    if redis_url is None:
        redis_url = "redis://localhost:6379/0"

    with _redis_lock:
        if redis_url not in _async_redis_pools:
            try:
                pool = async_redis.ConnectionPool.from_url(
                    redis_url,
                    **_build_pool_kwargs(settings),
                )
                _async_redis_pools[redis_url] = pool
                logger.info("Created new async Redis connection pool for %s", redis_url)
            except Exception as e:
                failure_mode = get_settings().runtime.failure_mode
                logger.error(
                    "Failed to initialize async Redis connection pool for %s: %s. runtime.failure_mode=%s",
                    redis_url,
                    e,
                    failure_mode,
                )
                if should_fail_fast(failure_mode):
                    raise
                logger.warning("Continuing without async Redis connection pool.")
                return None
        else:
            pool = _async_redis_pools[redis_url]

    return async_redis.Redis(connection_pool=pool)


def close_redis_pools() -> None:
    """Close and clear all synchronous and asynchronous Redis connection pools.

    Disconnect failures are logged rather than discarded: a pool that refuses
    to close is leaking sockets, and the previous ``except Exception: pass``
    made that invisible.
    """
    global _redis_pool
    with _redis_lock:
        for redis_url, pool in _redis_pools.items():
            try:
                pool.disconnect()
            except Exception:
                logger.warning(
                    "Failed to disconnect Redis pool for %s; connections may leak",
                    redis_url,
                    exc_info=True,
                )
        _redis_pools.clear()
        _redis_pool = None

        for redis_url, async_pool in list(_async_redis_pools.items()):
            _close_async_pool_from_sync(redis_url, async_pool)
        _async_redis_pools.clear()


def _close_async_pool_from_sync(redis_url: str, async_pool) -> None:
    """Disconnect an async pool from synchronous code.

    ``AsyncConnectionPool.disconnect()`` returns a coroutine. The previous code
    called ``.close()`` on it, which *cancels* the coroutine instead of running
    it -- so the pool was never actually disconnected, and the resulting
    "coroutine was never awaited" warning was swallowed by a bare except. The
    pools looked closed while their sockets stayed open.
    """
    try:
        res = async_pool.disconnect()
    except Exception:
        logger.warning(
            "Failed to disconnect async Redis pool for %s; connections may leak",
            redis_url,
            exc_info=True,
        )
        return

    if not inspect.isawaitable(res):
        return

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No loop is running, so we can drive the coroutine to completion.
        try:
            asyncio.run(_await_result(res))
        except Exception:
            logger.warning(
                "Failed to disconnect async Redis pool for %s; connections may leak",
                redis_url,
                exc_info=True,
            )
        return

    # A loop is already running on this thread: the coroutine cannot be driven
    # from here. Close it to avoid an un-awaited warning, and say plainly that
    # the pool is still open.
    close = getattr(res, "close", None)
    if close is not None:
        close()
    logger.warning(
        "close_redis_pools() called from a running event loop; the async Redis "
        "pool for %s was NOT disconnected. Await close_async_redis_pools() "
        "instead.",
        redis_url,
    )


async def _await_result(awaitable):
    """Await a value, for driving a coroutine from ``asyncio.run``."""
    return await awaitable


async def close_async_redis_pools() -> None:
    """Close all asynchronous Redis connection pools."""
    with _redis_lock:
        pools = list(_async_redis_pools.items())
        _async_redis_pools.clear()
    for redis_url, async_pool in pools:
        try:
            res = async_pool.disconnect()
            if inspect.isawaitable(res):
                await res
        except Exception:
            logger.warning(
                "Failed to disconnect async Redis pool for %s; connections may leak",
                redis_url,
                exc_info=True,
            )
