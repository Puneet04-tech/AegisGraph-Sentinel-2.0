"""
JSON serialization utilities for AegisGraph Sentinel.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Dict
from uuid import UUID

try:
    import numpy as np
except ImportError:
    np = None


def _default_serializer(obj: Any) -> Any:
    """Convert objects json.dumps cannot handle natively."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, Decimal):
        return float(obj)
    if np is not None:
        if isinstance(obj, np.generic):
            return obj.item()
        if isinstance(obj, np.ndarray):
            return obj.tolist()
    try:
        return str(obj)
    except Exception:
        raise TypeError(f"cannot serialize object of type {type(obj).__name__}")


def json_dumps(obj: Any, *, sort_keys: bool = False, **kwargs) -> str:
    """Serialize obj to JSON, handling dates, UUIDs, Decimals, and numpy types."""
    kwargs.setdefault("default", _default_serializer)
    return json.dumps(obj, sort_keys=sort_keys, **kwargs)


def json_loads(text: str) -> Any:
    """Deserialize a JSON string, raising JSONDecodeError on invalid input."""
    return json.loads(text)


def safe_json_dumps(obj: Any, *, default_str: str = "null", **kwargs) -> str:
    """Serialize obj to JSON; never raises, returns default_str on failure."""
    try:
        return json_dumps(obj, **kwargs)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return default_str


def deep_merge(base: Dict, override: Dict) -> Dict:
    """Recursively merge override into base, returning a new dict."""
    result = dict(base)
    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def to_camel_case(snake: str) -> str:
    """Convert a snake_case string to camelCase."""
    if not snake:
        return snake
    parts = snake.split("_")
    return parts[0] + "".join(part[:1].upper() + part[1:] for part in parts[1:])


def to_snake_case(camel: str) -> str:
    """Convert a camelCase or PascalCase string to snake_case."""
    if not camel:
        return camel
    snake = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", camel)
    snake = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", snake)
    return snake.lower()
