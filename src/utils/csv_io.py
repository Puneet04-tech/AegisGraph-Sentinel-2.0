"""
CSV file read/write utilities for AegisGraph Sentinel.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple

Row = Sequence[Any]
DictRows = Sequence[dict]


def read_csv_file(filepath, *, as_dicts: bool = True, encoding: str = "utf-8"):
    """Read a CSV file as a list of dicts (default) or list of lists."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found: {filepath}")
    with path.open("r", encoding=encoding, newline="") as fh:
        if as_dicts:
            return list(csv.DictReader(fh))
        return list(csv.reader(fh))


def write_csv_file(rows, filepath, *, field_names=None, encoding: str = "utf-8", append: bool = False) -> str:
    """Write dict or list rows to a CSV file; return the filepath."""
    path = Path(filepath)
    rows = list(rows)
    if field_names is None and rows and isinstance(rows[0], dict):
        field_names = list(rows[0].keys())
    write_header = field_names is not None and not append
    mode = "a" if append else "w"
    with path.open(mode, encoding=encoding, newline="") as fh:
        if field_names is not None:
            writer = csv.DictWriter(fh, fieldnames=field_names, extrasaction="ignore")
            if write_header:
                writer.writeheader()
            for row in rows:
                writer.writerow(row)
        else:
            writer = csv.writer(fh)
            writer.writerows(rows)
    return str(path)


def rows_to_dicts(rows: Sequence[Row], headers: Sequence[str]) -> List[dict]:
    """Convert rows of lists into dicts keyed by headers (shorter -> None, longer ignored)."""
    result = []
    for row in rows:
        result.append(
            {header: row[index] if index < len(row) else None for index, header in enumerate(headers)}
        )
    return result


def dicts_to_rows(dicts: DictRows, field_names: Optional[Sequence[str]] = None) -> Tuple[Sequence[str], List[Row]]:
    """Convert dicts into (headers, rows); headers come from the first dict unless given."""
    dicts = list(dicts)
    if field_names is None and dicts:
        field_names = list(dicts[0].keys())
    field_names = list(field_names or [])
    rows = [[row.get(header) for header in field_names] for row in dicts]
    return field_names, rows


def count_rows(filepath, *, skip_header: bool = True) -> int:
    """Count data rows in a CSV file, optionally skipping the header row."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found: {filepath}")
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        if skip_header:
            try:
                next(reader)
            except StopIteration:
                return 0
        count = 0
        for _ in reader:
            count += 1
        return count
