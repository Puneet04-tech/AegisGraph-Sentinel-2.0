"""Pure-Python UI helper utilities for AegisGraph Sentinel 2.0.

These functions contain no Streamlit, PyTorch, or NetworkX dependencies and
can therefore be imported and tested without any heavy libraries.  The
Streamlit ``app.py`` delegates to these helpers to keep testable logic
separate from rendering concerns.

Extracted from app.py as part of the ongoing modularisation effort tracked
in GitHub issue #854.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Set


# ---------------------------------------------------------------------------
# Required CSV column names for batch transaction upload.
# Validated before any row is sent to the API.
# ---------------------------------------------------------------------------
REQUIRED_CSV_COLUMNS: Set[str] = {
    "transaction_id",
    "source_account",
    "target_account",
    "amount",
}


# ---------------------------------------------------------------------------
# Decision classification
# ---------------------------------------------------------------------------

#: Maps normalised decision strings to a (severity, emoji, label) tuple.
#: ``severity`` is one of: ``"success"``, ``"warning"``, ``"error"``, ``"info"``
_DECISION_MAP: dict[str, tuple[str, str]] = {
    "SAFE":    ("success", "✅"),
    "ALLOW":   ("success", "✅"),
    "APPROVE": ("success", "✅"),
    "REVIEW":  ("warning", "⚠️"),
    "BLOCK":   ("error",   "🛑"),
}


def classify_decision(decision: str) -> tuple[str, str, str]:
    """Classify a fraud decision string into a (severity, emoji, label) triple.

    This is the pure-Python core of ``display_decision_badge()`` in ``app.py``.
    Separating the classification logic from the Streamlit rendering call makes
    it unit-testable without a running Streamlit server.

    Args:
        decision: Raw decision string from the API (case-insensitive).

    Returns:
        A tuple of ``(severity, emoji, normalised_label)`` where ``severity``
        is one of ``"success"``, ``"warning"``, ``"error"``, ``"info"``.

    Examples:
        >>> classify_decision("allow")
        ('success', '✅', 'ALLOW')
        >>> classify_decision("BLOCK")
        ('error', '🛑', 'BLOCK')
        >>> classify_decision("unknown")
        ('info', 'ℹ️', 'UNKNOWN')
    """
    normalised = str(decision).upper()
    severity, emoji = _DECISION_MAP.get(normalised, ("info", "ℹ️"))
    return severity, emoji, normalised


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def get_api_timestamp() -> str:
    """Return a strict ISO 8601 UTC timestamp (``YYYY-MM-DDTHH:MM:SSZ``) for the API.

    Uses second precision to match the format expected by FastAPI request schemas.

    Returns:
        Timestamp string, e.g. ``"2026-06-06T12:00:00Z"``.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Accessibility helpers
# ---------------------------------------------------------------------------

def accessible_status(emoji: str, label: str) -> str:
    """Return a visual status string with an adjacent plain-text equivalent.

    Screen readers may skip emoji characters.  Appending the plain-text label
    in parentheses ensures the status is conveyed to all users.

    Args:
        emoji: Unicode emoji (e.g. ``"✅"``).
        label: Plain-text label (e.g. ``"Safe"``).

    Returns:
        Combined string, e.g. ``"✅ Safe (Safe)"``.
    """
    return f"{emoji} {label} ({label})"


# ---------------------------------------------------------------------------
# Security helpers — safe serialisation for HTML/JS contexts
# ---------------------------------------------------------------------------

def escape_network_tooltip_value(value: object) -> str:
    """Escape a dynamic value for safe insertion into HTML tooltip attributes.

    Prevents XSS when graph node data (account IDs, amounts, etc.) is rendered
    inside ``data-*`` attributes or HTML tooltip strings in the network explorer.

    Args:
        value: Any Python value; converted to string before escaping.

    Returns:
        HTML-safe string with ``&``, ``<``, ``>``, ``"``, and ``'`` escaped.
    """
    return html.escape(str(value), quote=True)


def json_for_inline_script(value: object) -> str:
    """Serialise a Python value for safe injection into an inline ``<script>`` block.

    Uses ``ensure_ascii=False`` so that non-ASCII characters (e.g. Indian rupee
    symbol ₹, account names) are preserved rather than being escaped to ``\\uXXXX``,
    which improves readability in generated scripts.

    Args:
        value: A JSON-serialisable Python object (dict, list, str, int, float, bool).

    Returns:
        JSON string safe for direct embedding in a ``<script>`` block.

    Raises:
        TypeError: If ``value`` is not JSON-serialisable.
    """
    return json.dumps(value, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CSV validation helpers
# ---------------------------------------------------------------------------

def validate_csv_columns(columns: Set[str]) -> list[str]:
    """Return a list of column names that are missing from a CSV upload.

    Args:
        columns: Set of column names present in the uploaded DataFrame
                 (typically ``set(df.columns)``).

    Returns:
        Sorted list of missing required column names, or an empty list if all
        required columns are present.

    Examples:
        >>> validate_csv_columns({"transaction_id", "source_account"})
        ['amount', 'target_account']
        >>> validate_csv_columns({"transaction_id", "source_account", "target_account", "amount"})
        []
    """
    missing = REQUIRED_CSV_COLUMNS - columns
    return sorted(missing)
