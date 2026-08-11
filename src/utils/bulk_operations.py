"""Helpers for processing items in bulk.

Provides chunking of iterables, batch-wise function application, and
per-item retry semantics suitable for bulk ingestion pipelines.
"""

from typing import Any, Callable, Iterable, Iterator, List


def chunked(iterable: Iterable[Any], size: int) -> Iterator[List[Any]]:
    """Yield successive ``size``-sized chunks from ``iterable``.

    The final chunk may be smaller than ``size``. Raises ``ValueError``
    when ``size`` is not positive.
    """
    if size <= 0:
        raise ValueError("size must be positive")

    batch: List[Any] = []
    for item in iterable:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def process_in_batches(
    items: Iterable[Any],
    batch_size: int,
    func: Callable[[List[Any]], Any],
) -> List[Any]:
    """Apply ``func(batch)`` to each chunk of ``items``.

    Returns one result per batch, preserving batch order.
    """
    return [func(batch) for batch in chunked(items, batch_size)]


def execute_with_retry_per_item(
    items: Iterable[Any],
    func: Callable[[Any], Any],
    *,
    max_attempts: int = 2,
) -> dict:
    """Run ``func(item)`` for each item, retrying failures.

    Returns ``{"success": [...], "failed": [{"item": ..., "error": str}]}``.
    Each item appears at most once across the two lists; an item that
    exhausts all attempts is recorded in ``failed`` with its last error.
    """
    success: List[Any] = []
    failed: List[dict] = []

    for item in items:
        last_error: Exception | None = None
        for attempt in range(max_attempts):
            try:
                result = func(item)
                success.append(result)
                last_error = None
                break
            except Exception as exc:  # noqa: BLE001 - captured per item
                last_error = exc
        if last_error is not None:
            failed.append({"item": item, "error": str(last_error)})

    return {"success": success, "failed": failed}


def summarize_results(results: dict) -> dict:
    """Summarize the outcome of :func:`execute_with_retry_per_item`.

    Returns ``{"success_count": int, "failed_count": int, "total": int,
    "success_rate": float}``. An empty result set yields a 0.0 rate.
    """
    success_count = len(results["success"])
    failed_count = len(results["failed"])
    total = success_count + failed_count
    success_rate = success_count / total if total else 0.0
    return {
        "success_count": success_count,
        "failed_count": failed_count,
        "total": total,
        "success_rate": success_rate,
    }
