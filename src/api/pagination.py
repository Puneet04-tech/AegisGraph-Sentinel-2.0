"""Pagination helpers for AegisGraph Sentinel 2.0 API responses.

Provides offset/limit pagination via ``paginate``/``parse_pagination_params``
and cursor-based pagination via ``paginate_cursor`` for large, append-only
result sets where offset pagination becomes unstable.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 1000


def parse_pagination_params(
    page: str | int | None = None,
    page_size: str | int | None = None,
) -> tuple[int, int]:
    """Normalize ``page``/``page_size`` query params into safe ints.

    Non-numeric strings fall back to the defaults, negatives are clamped,
    and ``page_size`` is capped at ``MAX_PAGE_SIZE``.
    """
    try:
        page = int(page)
    except (TypeError, ValueError):
        page = 1
    if page < 1:
        page = 1

    try:
        page_size = int(page_size)
    except (TypeError, ValueError):
        page_size = DEFAULT_PAGE_SIZE
    if page_size < 1:
        page_size = DEFAULT_PAGE_SIZE
    if page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE

    return page, page_size


def paginate(
    items: Sequence[Any],
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> dict[str, Any]:
    """Slice ``items`` into a single offset-based page and describe it."""
    page, page_size = parse_pagination_params(page, page_size)
    total = len(items)
    pages = (total + page_size - 1) // page_size if total else 0
    start = (page - 1) * page_size
    page_items = list(items[start : start + page_size])
    return {
        "items": page_items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "pages": pages,
        "has_next": page < pages,
        "has_prev": page > 1 and pages > 0,
    }


def paginate_cursor(
    items: Sequence[Any],
    cursor: str | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
    key: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    """Return items after ``cursor`` in an already key-ascending sequence.

    ``items`` must be pre-sorted ascending by ``key``. ``next_cursor`` is the
    string form of the last returned item's key, or None when the page ends
    at (or beyond) the last item.
    """
    get_key = key if key is not None else lambda item: item
    if limit < 1:
        limit = DEFAULT_PAGE_SIZE
    if limit > MAX_PAGE_SIZE:
        limit = MAX_PAGE_SIZE

    start = 0
    if cursor is not None:
        for i, item in enumerate(items):
            if str(get_key(item)) > cursor:
                start = i
                break
        else:
            start = len(items)

    page_items = list(items[start : start + limit])
    next_cursor = None
    if start + limit < len(items):
        next_cursor = str(get_key(page_items[-1]))
    return {"items": page_items, "next_cursor": next_cursor, "limit": limit}
