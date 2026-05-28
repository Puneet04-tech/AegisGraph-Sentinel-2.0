"""Service boundary for centralized risk scoring."""

from __future__ import annotations

from typing import Any, Dict, Optional, Protocol


class ScoringService(Protocol):
    """Protocol defining the core assessment scoring interface."""

    def assess(
        self,
        component_scores: Dict[str, float],
        metadata: Optional[Dict[str, str]] = None,
    ) -> Any:
        ...
