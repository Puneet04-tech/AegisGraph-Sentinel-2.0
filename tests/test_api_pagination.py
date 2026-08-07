"""Tests for the API pagination helpers in ``src.api.pagination``.

Covers offset-based pagination (``paginate``), query-param normalization
(``parse_pagination_params``), and cursor-based pagination
(``paginate_cursor``), including boundary, clamping, and edge-case
behaviour.
"""

from __future__ import annotations

import pytest

from src.api.pagination import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    paginate,
    paginate_cursor,
    parse_pagination_params,
)


def test_basic_first_page_slice():
    result = paginate(list(range(25)), page=1, page_size=10)
    assert result["items"] == list(range(10))
    assert result["page"] == 1
    assert result["page_size"] == 10
    assert result["total"] == 25
    assert result["pages"] == 3
    assert result["has_prev"] is False
    assert result["has_next"] is True


def test_middle_page_slice():
    result = paginate(list(range(25)), page=2, page_size=10)
    assert result["items"] == list(range(10, 20))
    assert result["has_prev"] is True
    assert result["has_next"] is True


def test_last_partial_page():
    result = paginate(list(range(25)), page=3, page_size=10)
    assert result["items"] == list(range(20, 25))
    assert result["total"] == 25
    assert result["pages"] == 3
    assert result["has_prev"] is True
    assert result["has_next"] is False


def test_out_of_range_page_returns_empty_items():
    result = paginate(list(range(25)), page=5, page_size=10)
    assert result["items"] == []
    assert result["total"] == 25
    assert result["pages"] == 3
    assert result["has_next"] is False
    assert result["has_prev"] is True


def test_page_below_one_clamped_to_first():
    result = paginate(list(range(25)), page=0, page_size=10)
    assert result["page"] == 1
    assert result["items"] == list(range(10))


def test_page_size_below_one_uses_default():
    result = paginate(list(range(25)), page=1, page_size=0)
    assert result["page_size"] == DEFAULT_PAGE_SIZE
    assert result["items"] == list(range(25))
    assert result["total"] == 25


def test_page_size_above_max_clamped():
    result = paginate(list(range(25)), page=1, page_size=100_000)
    assert result["page_size"] == MAX_PAGE_SIZE
    assert result["items"] == list(range(25))
    assert result["pages"] == 1


def test_page_size_negative_uses_default():
    result = paginate(list(range(25)), page=1, page_size=-5)
    assert result["page_size"] == DEFAULT_PAGE_SIZE


def test_exact_multiple_page_count():
    result = paginate(list(range(20)), page=2, page_size=10)
    assert result["total"] == 20
    assert result["pages"] == 2
    assert result["has_next"] is False


def test_empty_list():
    result = paginate([], page=1, page_size=10)
    assert result["items"] == []
    assert result["total"] == 0
    assert result["pages"] == 0
    assert result["has_next"] is False
    assert result["has_prev"] is False


def test_tuple_sequence_supported():
    result = paginate((1, 2, 3, 4), page=2, page_size=3)
    assert result["items"] == [4]
    assert result["total"] == 4


def test_parse_valid_ints_passthrough():
    assert parse_pagination_params(2, 15) == (2, 15)


def test_parse_none_defaults():
    assert parse_pagination_params(None, None) == (1, DEFAULT_PAGE_SIZE)


def test_parse_invalid_strings_use_defaults():
    assert parse_pagination_params("abc", "xyz") == (1, DEFAULT_PAGE_SIZE)


def test_parse_partial_invalid_string():
    assert parse_pagination_params("3", "nope") == (3, DEFAULT_PAGE_SIZE)
    assert parse_pagination_params("nope", "20") == (1, 20)


def test_parse_negative_values_clamped():
    assert parse_pagination_params(-2, -1) == (1, DEFAULT_PAGE_SIZE)


def test_parse_string_ints_accepted():
    assert parse_pagination_params("2", "25") == (2, 25)


def test_parse_page_size_capped_at_max():
    assert parse_pagination_params(1, 9999) == (1, MAX_PAGE_SIZE)


def test_cursor_full_iteration_reconstructs_list():
    items = [f"id-{i:03d}" for i in range(100)]
    cursor = None
    collected = []
    for _ in range(10):
        result = paginate_cursor(items, cursor=cursor, limit=12)
        collected.extend(result["items"])
        cursor = result["next_cursor"]
        if cursor is None:
            break
    assert collected == items


def test_cursor_next_cursor_none_on_last_page():
    result = paginate_cursor(["a", "b", "c"], cursor=None, limit=10)
    assert result["items"] == ["a", "b", "c"]
    assert result["next_cursor"] is None


def test_cursor_returns_items_after_cursor():
    result = paginate_cursor(["a", "b", "c", "d"], cursor="b", limit=2)
    assert result["items"] == ["c", "d"]
    assert result["next_cursor"] is None


def test_cursor_uses_key_callable():
    items = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
    result = paginate_cursor(items, cursor="a", limit=1, key=lambda x: x["name"])
    assert result["items"] == [{"name": "b"}]
    assert result["next_cursor"] == "b"


def test_cursor_cursor_beyond_all_items_returns_empty():
    result = paginate_cursor(["a", "b"], cursor="z", limit=5)
    assert result["items"] == []
    assert result["next_cursor"] is None


def test_cursor_empty_items():
    result = paginate_cursor([], cursor=None, limit=5)
    assert result["items"] == []
    assert result["next_cursor"] is None


def test_cursor_limit_default_and_clamping():
    small = paginate_cursor(["a", "b"], limit=0)
    assert small["limit"] == DEFAULT_PAGE_SIZE
    huge = paginate_cursor(["a", "b"], limit=9999)
    assert huge["limit"] == MAX_PAGE_SIZE
