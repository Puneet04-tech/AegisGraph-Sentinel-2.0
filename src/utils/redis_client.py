import logging
import threading
from typing import Optional

import redis

from src.config.settings import get_settings

from ..config import get_settings
from ..runtime.failure_policy import should_fail_fast

logger = logging.getLogger(__name__)

_redis_pool = None
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


def get_redis_client(redis_url: Optional[str] = None) -> redis.Redis:
    """Get or create Redis client using a global connection pool.

    Provides thread-safe access to Redis connection.
    """
    global _redis_pool
    settings = get_settings()
    database = settings.database
    if redis_url is None:
        redis_url = database.redis_url
    if redis_url is None:
        redis_url = "redis://localhost:6379/0"

    if _redis_pool is None:
        with _redis_lock:
            if _redis_pool is None:
                try:
                    _redis_pool = redis.ConnectionPool.from_url(
                        redis_url,
                        **_build_pool_kwargs(settings),
                    )
                    logger.info("Created new Redis connection pool")
                except Exception as e:
                    failure_mode = get_settings().runtime.failure_mode
                    logger.error(
                        "Failed to initialize Redis connection pool: %s. runtime.failure_mode=%s",
                        e,
                        failure_mode,
                    )
                    if should_fail_fast(failure_mode):
                        raise
                    logger.warning("Continuing without Redis connection pool.")
                    return redis.Redis()
            
    return redis.Redis(connection_pool=_redis_pool)
