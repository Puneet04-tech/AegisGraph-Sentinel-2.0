"""Lightweight runtime policy rule model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Any


@dataclass
class PolicyRule:
    """A named runtime policy backed by a simple Python evaluator."""

    name: str
    description: str
    enabled: bool
    evaluator: Callable[[Dict[str, Any]], bool]
