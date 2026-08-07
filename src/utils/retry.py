"""Retry helper with exponential backoff and full jitter.

Provides a small, dependency-free way to make fallible operations
resilient. The ``retry`` decorator wraps both synchronous and
asynchronous callables and applies a configurable retry policy.
"""

import asyncio
import functools
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Tuple, Type


@dataclass
class RetryPolicy:
    """Configuration for retry behavior."""

    max_attempts: int = 3
    base_delay: float = 0.1
    max_delay: float = 5.0
    backoff_factor: float = 2.0
    jitter: bool = True
    retry_on: Tuple[Type[BaseException], ...] = (Exception,)
    on_retry: Optional[Callable[[BaseException, int], None]] = None

    def __post_init__(self) -> None:
        if self.max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if self.base_delay < 0 or self.max_delay < 0:
            raise ValueError("delays must be non-negative")
        if self.backoff_factor <= 0:
            raise ValueError("backoff_factor must be positive")


def _should_retry(exc: BaseException, policy: RetryPolicy) -> bool:
    return isinstance(exc, policy.retry_on)


def _sleep(delay: float) -> None:
    time.sleep(delay)


def _compute_delay(attempt: int, policy: RetryPolicy) -> float:
    exponential = policy.base_delay * (policy.backoff_factor ** attempt)
    delay = min(exponential, policy.max_delay)
    if policy.jitter:
        delay = random.uniform(0, delay)
    return delay


def retry(policy: Optional[RetryPolicy] = None, **kwargs: Any) -> Callable:
    """Decorator factory applying ``policy`` (or keyword overrides).

    Usage::

        @retry(max_attempts=4, base_delay=0.01)
        def flaky_call() -> str: ...

        @retry
        async def flaky_async() -> str: ...
    """
    if isinstance(policy, RetryPolicy):
        pass
    elif policy is None:
        policy = RetryPolicy(**kwargs) if kwargs else RetryPolicy()
    elif callable(policy):
        return retry(**kwargs)(policy)
    else:
        policy = RetryPolicy(**policy, **kwargs)

    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kw: Any) -> Any:
                last_error: Optional[BaseException] = None
                for attempt in range(policy.max_attempts):
                    try:
                        return await func(*args, **kw)
                    except BaseException as exc:  # noqa: BLE001 - policy driven
                        last_error = exc
                        if not _should_retry(exc, policy) or attempt == policy.max_attempts - 1:
                            raise
                        if policy.on_retry:
                            policy.on_retry(exc, attempt + 1)
                        await asyncio.sleep(_compute_delay(attempt, policy))
                raise last_error  # type: ignore[misc]

            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args: Any, **kw: Any) -> Any:
            last_error: Optional[BaseException] = None
            for attempt in range(policy.max_attempts):
                try:
                    return func(*args, **kw)
                except BaseException as exc:  # noqa: BLE001 - policy driven
                    last_error = exc
                    if not _should_retry(exc, policy) or attempt == policy.max_attempts - 1:
                        raise
                    if policy.on_retry:
                        policy.on_retry(exc, attempt + 1)
                    _sleep(_compute_delay(attempt, policy))
            raise last_error  # type: ignore[misc]

        return wrapper

    return decorator


def retry_sync(func: Callable, policy: Optional[RetryPolicy] = None, *args: Any, **kwargs: Any) -> Any:
    """Directly invoke ``func(*args, **kwargs)`` with a retry policy."""
    return retry(policy)(func)(*args, **kwargs)
