"""
Tests for src/utils/csv_io.py.
"""
from __future__ import annotations

import csv

import pytest

from src.utils.csv_io import (
    count_rows,
    dicts_to_rows,
    read_csv_file,
    rows_to_dicts,
    write_csv_file,
)


def test_round_trip_dicts_through_write_and_read(tmp_path):
    path = tmp_path / "transactions.csv"
    rows = [
        {"account": "acct_1", "amount": "250.75", "risk": "high"},
        {"account": "acct_2", "amount": "12.00", "risk": "low"},
    ]
    write_csv_file(rows, path)
    assert read_csv_file(path) == rows


def test_read_csv_file_as_lists(tmp_path):
    path = tmp_path / "plain.csv"
    path.write_text("name,score\nada,98\nbob,87\n", encoding="utf-8")
    assert read_csv_file(path, as_dicts=False) == [
        ["name", "score"],
        ["ada", "98"],
        ["bob", "87"],
    ]


def test_read_empty_file_returns_empty_list(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("", encoding="utf-8")
    assert read_csv_file(path) == []
    assert read_csv_file(path, as_dicts=False) == []


def test_read_missing_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_csv_file(tmp_path / "nope.csv")


def test_write_csv_file_auto_detects_field_names(tmp_path):
    path = tmp_path / "out.csv"
    write_csv_file(
        [{"a": 1, "b": 2}, {"a": 3, "b": 4}],
        path,
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines == ["a,b", "1,2", "3,4"]


def test_write_csv_file_field_names_override_order(tmp_path):
    path = tmp_path / "ordered.csv"
    write_csv_file(
        [{"a": 1, "b": 2, "c": 3}],
        path,
        field_names=["c", "a"],
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines == ["c,a", "3,1"]


def test_write_csv_file_list_rows_without_header(tmp_path):
    path = tmp_path / "lists.csv"
    write_csv_file([[1, 2], [3, 4]], path)
    assert read_csv_file(path, as_dicts=False) == [["1", "2"], ["3", "4"]]


def test_append_mode_does_not_rewrite_header(tmp_path):
    path = tmp_path / "append.csv"
    write_csv_file([{"x": 1}], path)
    write_csv_file([{"x": 2}, {"x": 3}], path, append=True)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines == ["x", "1", "2", "3"]


def test_rows_to_dicts_normal():
    rows = [["ada", 98], ["bob", 87]]
    assert rows_to_dicts(rows, ["name", "score"]) == [
        {"name": "ada", "score": 98},
        {"name": "bob", "score": 87},
    ]


def test_rows_to_dicts_short_row_uses_none():
    assert rows_to_dicts([["ada"]], ["name", "score"]) == [
        {"name": "ada", "score": None}
    ]


def test_rows_to_dicts_long_row_extra_ignored():
    assert rows_to_dicts([["ada", 98, "extra"]], ["name", "score"]) == [
        {"name": "ada", "score": 98}
    ]


def test_dicts_to_rows_returns_headers_and_rows():
    dicts = [{"name": "ada", "score": 98}, {"name": "bob", "score": 87}]
    assert dicts_to_rows(dicts) == (
        ["name", "score"],
        [["ada", 98], ["bob", 87]],
    )


def test_dicts_to_rows_with_field_names_order():
    dicts = [{"name": "ada", "score": 98}]
    assert dicts_to_rows(dicts, field_names=["score", "name"]) == (
        ["score", "name"],
        [[98, "ada"]],
    )


def test_dicts_to_rows_empty_input():
    assert dicts_to_rows([]) == ([], [])


def test_count_rows_skip_header(tmp_path):
    path = tmp_path / "count.csv"
    write_csv_file([{"a": 1}, {"a": 2}, {"a": 3}], path)
    assert count_rows(path) == 3
    assert count_rows(path, skip_header=False) == 4


def test_count_rows_empty_file(tmp_path):
    path = tmp_path / "count_empty.csv"
    path.write_text("", encoding="utf-8")
    assert count_rows(path) == 0


def test_round_trip_preserves_special_characters(tmp_path):
    path = tmp_path / "special.csv"
    original = [
        {"note": 'say "hi" there', "city": "Amsterdam, NL"},
        {"note": "caf\u00e9 \u4e2d\u6587 \u00e9\u00e8", "city": "m\u00fcnchen"},
    ]
    write_csv_file(original, path)
    assert read_csv_file(path) == original


def test_round_trip_via_csv_module_consistency(tmp_path):
    path = tmp_path / "module.csv"
    rows = [{"k": "a,b"}, {"k": '"quoted"'}]
    write_csv_file(rows, path)
    with path.open("r", encoding="utf-8", newline="") as fh:
        parsed = list(csv.DictReader(fh))
    assert parsed == rows
