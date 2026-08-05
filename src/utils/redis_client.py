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
    global _redis_pools, _redis_pool
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
    global _async_redis_pools
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
    """Close and clear all synchronous and asynchronous Redis connection pools."""
    global _redis_pools, _async_redis_pools, _redis_pool
    with _redis_lock:
        for pool in _redis_pools.values():
            try:
                pool.disconnect()
            except Exception:
                pass
        _redis_pools.clear()
        _redis_pool = None

        for async_pool in _async_redis_pools.values():
            try:
                res = async_pool.disconnect()
                if inspect.isawaitable(res):
                    res.close()
            except Exception:
                pass
        _async_redis_pools.clear()


async def close_async_redis_pools() -> None:
    """Close all asynchronous Redis connection pools."""
    global _async_redis_pools
    with _redis_lock:
        pools = list(_async_redis_pools.values())
        _async_redis_pools.clear()
    for async_pool in pools:
        try:
            res = async_pool.disconnect()
            if inspect.isawaitable(res):
                await res
        except Exception:
            pass
