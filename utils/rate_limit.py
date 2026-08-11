import threading
import time
from typing import Callable, Dict, Optional, Any
from .rate_limiter import RateLimiter


class TokenBucketRateLimiter:
    """
    Per-client IP Token-Bucket Rate Limiter for Streamlit dashboard endpoints.
    
    Default: 5 requests per 60 seconds (capacity=5, refill_rate=5/60 tokens/sec).
    """

    def __init__(self, capacity: float = 5.0, window_seconds: float = 60.0):
        self.capacity = float(capacity)
        self.window_seconds = float(window_seconds)
        self.refill_rate = capacity / window_seconds
        self._limiters: Dict[str, RateLimiter] = {}
        self._lock = threading.Lock()

    def get_limiter(self, key: str) -> RateLimiter:
        """Get or create rate limiter instance for client key."""
        with self._lock:
            if key not in self._limiters:
                self._limiters[key] = RateLimiter(
                    capacity=self.capacity,
                    refill_rate=self.refill_rate,
                )
            return self._limiters[key]

    def consume(self, key: str, tokens: int = 1) -> bool:
        """Attempt to consume tokens for specified client key."""
        limiter = self.get_limiter(key)
        return limiter.consume(tokens)


# Global rate limiter instance for Streamlit endpoints
_streamlit_limiter = TokenBucketRateLimiter(capacity=5.0, window_seconds=60.0)


def rate_limit_streamlit(
    key: str = "default_client",
    limiter: Optional[TokenBucketRateLimiter] = None,
) -> Callable:
    """
    Decorator for Streamlit dashboard prediction endpoints.
    Renders st.error message when rate limit threshold is exceeded.
    """
    limiter_instance = limiter or _streamlit_limiter

    def decorator(func: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not limiter_instance.consume(key):
                import streamlit as st
                st.error("Too many requests. Please try again after 60 seconds.")
                return None
            return func(*args, **kwargs)
        return wrapper
    return decorator
