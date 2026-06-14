import math
from typing import Any, Dict, Iterable, List, Optional, Set


class EdgeCaseHandler:
    """Utility helpers for safe score and weight handling."""

    @staticmethod
    def safe_score(value: Any) -> float:
        try:
            score = float(value)
        except (TypeError, ValueError):
            return 0.0

        if math.isnan(score) or math.isinf(score):
            return 0.0

        return max(0.0, min(1.0, score))

    @staticmethod
    def safe_float(
        value: Any,
        default: float = 0.0,
        min_value: float = 0.0,
        max_value: float = 1.0,
    ) -> float:
        if min_value >= max_value:
            raise ValueError("min_value must be less than max_value")

        try:
            result = float(value)
        except (TypeError, ValueError):
            return default

        if math.isnan(result) or math.isinf(result):
            return default

        return max(min_value, min(max_value, result))

    @staticmethod
    def safe_weights(
        weights: Optional[Dict[str, Any]],
        keys: Optional[Iterable[str]] = None,
    ) -> Dict[str, float]:
        if not weights or not isinstance(weights, dict):
            return EdgeCaseHandler._equal_weights(keys)

        validated_weights: Dict[str, float] = {}
        for component, value in weights.items():
            validated_weights[component] = EdgeCaseHandler.safe_float(value, default=0.0, min_value=0.0, max_value=1.0)

        if keys is not None:
            validated_weights = {
                key: validated_weights.get(key, 0.0)
                for key in keys
            }

        total = sum(validated_weights.values())
        if total <= 0.0:
            return EdgeCaseHandler._equal_weights(keys)

        return {k: v / total for k, v in validated_weights.items()}

    @staticmethod
    def _equal_weights(keys: Optional[Iterable[str]]) -> Dict[str, float]:
        if not keys:
            return {}

        key_list = list(keys)
        if not key_list:
            return {}

        equal_weight = 1.0 / len(key_list)
        return {key: equal_weight for key in key_list}

    @staticmethod
    def safe_components(components: Optional[Dict[str, Any]]) -> Dict[str, float]:
        if not components or not isinstance(components, dict):
            return {}

        return {
            name: EdgeCaseHandler.safe_score(value)
            for name, value in components.items()
        }

    @staticmethod
    def detect_circular_transfers(
        transactions: Optional[List[Dict[str, Any]]],
        source_field: str = "source_account",
        target_field: str = "target_account",
        max_cycle_length: int = 10,
    ) -> List[List[str]]:
        if not transactions or not isinstance(transactions, list):
            return []

        adjacency: Dict[str, Set[str]] = {}
        for txn in transactions:
            if not isinstance(txn, dict):
                continue
            source = txn.get(source_field)
            target = txn.get(target_field)
            if not source or not target:
                continue
            adjacency.setdefault(str(source), set()).add(str(target))

        cycles: List[List[str]] = []
        visited: Set[str] = set()

        def dfs(node: str, path: List[str], stack: Set[str]) -> None:
            if len(path) > max_cycle_length:
                return
            for neighbor in adjacency.get(node, []):
                if neighbor in path:
                    cycle = path[path.index(neighbor):] + [neighbor]
                    if len(cycle) > 1 and cycle not in cycles:
                        cycles.append(cycle)
                elif neighbor not in stack:
                    dfs(neighbor, path + [neighbor], stack | {neighbor})

        for start_node in adjacency:
            if start_node in visited:
                continue
            dfs(start_node, [start_node], {start_node})
            for cycle in cycles:
                visited.update(cycle)
            visited.add(start_node)  

        return cycles 

    @staticmethod
    def has_circular_transfers(
        transactions: Optional[List[Dict[str, Any]]],
        source_field: str = "source_account",
        target_field: str = "target_account",
        max_cycle_length: int = 10,
    ) -> bool:
        return bool(EdgeCaseHandler.detect_circular_transfers(
            transactions,
            source_field=source_field,
            target_field=target_field,
            max_cycle_length=max_cycle_length,
        ))
