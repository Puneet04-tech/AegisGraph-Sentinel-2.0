"""Export and summarize audit trail records."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

Record = Dict[str, Any]


def to_csv(
    records: Sequence[Record],
    field_names: Optional[Sequence[str]] = None,
    *,
    filepath: Optional[str] = None,
) -> str:
    if field_names is None:
        field_names = []
        seen: set = set()
        for record in records:
            for key in record:
                if key not in seen:
                    seen.add(key)
                    field_names.append(key)
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=field_names)
    writer.writeheader()
    for record in records:
        writer.writerow({key: record.get(key, "") for key in field_names})
    csv_string = buffer.getvalue()
    if filepath is not None:
        with open(filepath, "w", newline="", encoding="utf-8") as handle:
            handle.write(csv_string)
        return filepath
    return csv_string


def to_json(
    records: Sequence[Record],
    *,
    filepath: Optional[str] = None,
    indent: int = 2,
) -> str:
    json_string = json.dumps(list(records), ensure_ascii=False, indent=indent)
    if filepath is not None:
        with open(filepath, "w", encoding="utf-8") as handle:
            handle.write(json_string)
        return filepath
    return json_string


def _ts_as_string(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _ts_cmp(value: Any, bound: Any, *, after: bool) -> bool:
    if isinstance(bound, datetime):
        if not isinstance(value, datetime):
            return False
        return value > bound if after else value < bound
    if not isinstance(value, str):
        return False
    return value > bound if after else value < bound


def filter_records(
    records: Sequence[Record],
    *,
    action: Optional[str] = None,
    user: Optional[str] = None,
    after: Any = None,
    before: Any = None,
) -> List[Record]:
    filtered: List[Record] = []
    for record in records:
        if action is not None and record.get("action") != action:
            continue
        if user is not None and record.get("user") != user:
            continue
        if after is not None and not _ts_cmp(record.get("timestamp"), after, after=True):
            continue
        if before is not None and not _ts_cmp(record.get("timestamp"), before, after=False):
            continue
        filtered.append(record)
    return filtered


def summarize(records: Sequence[Record]) -> Dict[str, Any]:
    actions: Dict[str, int] = {}
    users: Dict[str, int] = {}
    timestamps: List[str] = []
    for record in records:
        action = record.get("action")
        user = record.get("user")
        timestamp = record.get("timestamp")
        if action is not None:
            actions[action] = actions.get(action, 0) + 1
        if user is not None:
            users[user] = users.get(user, 0) + 1
        if timestamp is not None:
            timestamps.append(_ts_as_string(timestamp))
    return {
        "total": len(records),
        "actions": actions,
        "users": users,
        "first_ts": min(timestamps) if timestamps else None,
        "last_ts": max(timestamps) if timestamps else None,
    }
