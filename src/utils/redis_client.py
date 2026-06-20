import os
import redis
import logging
import threading

logger = logging.getLogger(__name__)

_redis_pool = None
_redis_lock = threading.Lock()

def get_redis_client(redis_url: str = None) -> redis.Redis:
    """Get or create Redis client using a global connection pool.
    
    Provides thread-safe access to Redis connection.
    """
    global _redis_pool
    if redis_url is None:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        
    if _redis_pool is None:
        with _redis_lock:
            if _redis_pool is None:
                try:
                    _redis_pool = redis.ConnectionPool.from_url(redis_url, decode_responses=True)
                    logger.info("Created new Redis connection pool")
                except Exception as e:
                    logger.error(f"Failed to initialize Redis connection pool: {e}")
                    raise e
            
    return redis.Redis(connection_pool=_redis_pool)
