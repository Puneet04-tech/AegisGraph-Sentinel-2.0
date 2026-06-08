"""Small UUID-based correlation helpers."""

from __future__ import annotations

import uuid
from typing import Optional


def generate_correlation_id() -> str:
    return str(uuid.uuid4())


def get_correlation_id(correlation_id: Optional[str] = None) -> str:
    return correlation_id or generate_correlation_id()
