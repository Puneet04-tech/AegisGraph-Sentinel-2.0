"""Service boundary for graph and database services."""

from __future__ import annotations

from typing import Any, Protocol


class GraphService(Protocol):
    """Protocol defining transaction graph lookup and statistics access."""

    @property
    def number_of_nodes(self) -> int:
        ...

    @property
    def number_of_edges(self) -> int:
        ...

    def nodes(self) -> Any:
        ...

    def edges(self) -> Any:
        ...
