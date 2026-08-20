"""Concurrency helpers built on ``concurrent.futures``.

Provides a shutdown-safe executor context manager plus two small
helpers for running callables in a thread pool: one that maps items
to results while preserving input order, and one that enforces a
wall-clock timeout on a single callable.
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable, List, Optional, Sequence


class ThreadPoolExecutorContext:
    """Context manager that always shuts the executor down on exit."""

    def __init__(self, *, max_workers: Optional[int] = None) -> None:
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    def __enter__(self) -> ThreadPoolExecutor:
        return self.executor

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.executor.shutdown(wait=True)


def run_parallel(
    func: Callable[[Any], Any],
    items: Iterable[Any],
    *,
    max_workers: Optional[int] = None,
    return_exceptions: bool = False,
) -> List[Any]:
    """Run ``func`` over each item in a thread pool, preserving input order.

    When ``return_exceptions`` is True, exceptions raised by ``func`` are
    returned in place of results instead of being re-raised.
    """
    sequence: Sequence[Any] = list(items)
    with ThreadPoolExecutorContext(max_workers=max_workers) as executor:
        futures = [executor.submit(func, item) for item in sequence]
        if not return_exceptions:
            return [f.result() for f in futures]

        results: List[Any] = []
        for future in futures:
            error = future.exception()
            results.append(error if error is not None else future.result())
        return results


def run_with_timeout(func: Callable[..., Any], timeout: float, *args: Any, **kwargs: Any) -> Any:
    """Run ``func(*args, **kwargs)`` in a thread, raising TimeoutError if slow."""
    with ThreadPoolExecutorContext(max_workers=1) as executor:
        future = executor.submit(func, *args, **kwargs)
        return future.result(timeout=timeout)
