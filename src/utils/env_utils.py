"""Environment variable helpers for safe, typed configuration access.

Thin wrappers around ``os.getenv`` that turn raw strings into booleans,
integers, floats, and lists, and provide safe redaction for logging.
"""

import os
from typing import Any, List, Optional

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    """Return the env var value, or ``default`` when missing or empty."""
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value


def get_bool_env(name: str, default: bool = False) -> bool:
    """Parse an env var into a boolean.

    ``1``/``true``/``yes``/``on`` (case-insensitive) are ``True``,
    ``0``/``false``/``no``/``off`` are ``False``, anything else falls
    back to ``default``.
    """
    value = get_env(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return default


def get_int_env(name: str, default: int = 0) -> int:
    """Parse an env var into an int, falling back on parse errors."""
    value = get_env(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def get_float_env(name: str, default: float = 0.0) -> float:
    """Parse an env var into a float, falling back on parse errors."""
    value = get_env(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def get_list_env(
    name: str, default: Optional[List[str]] = None, sep: str = ","
) -> List[str]:
    """Parse an env var into a list, splitting on ``sep``.

    Items are stripped and empty entries dropped. Missing or empty
    variables return ``default`` (or ``[]`` when ``default`` is None).
    """
    value = get_env(name)
    if value is None:
        return default if default is not None else []
    items = [item.strip() for item in value.split(sep)]
    return [item for item in items if item]


def env_required(name: str) -> str:
    """Return the env var value or raise if it is missing or empty."""
    value = get_env(name)
    if value is None:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def mask_env_value(name: str) -> str:
    """Return a log-safe representation that never leaks the actual value."""
    if get_env(name) is None:
        return f"{name}=<unset>"
    return f"{name}=<redacted>"
