"""Lightweight authorization permission rule."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AuthorizationRule:
    permission: str
    description: str = ""
    enabled: bool = True
