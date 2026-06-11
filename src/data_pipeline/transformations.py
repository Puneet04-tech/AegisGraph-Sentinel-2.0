"""
Data Transformations Module.

Data transformation operations.
"""

from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
import ast
import logging
import operator

from .models import (
    DataTransformation,
    TransformType,
)
from .store import PipelineStore, get_pipeline_store

logger = logging.getLogger(__name__)


class DataTransformer:
    """Data Transformer for data manipulation.
    
    Provides:
        - Data cleansing
        - Field mapping
        - Aggregations
        - Custom transformations
    """
    
    def __init__(self, store: Optional[PipelineStore] = None):
        """Initialize the data transformer."""
        self._store = store or get_pipeline_store()
        self._module_id = "transformations"
    
    def create_transform(
        self,
        name: str,
        transform_type: TransformType,
        config: Dict[str, Any],
        order: int = 0,
    ) -> DataTransformation:
        """Create a new transformation."""
        logger.info(f"Creating transformation: {name}")
        
        transform = DataTransformation(
            name=name,
            transform_type=transform_type,
            config=config,
            order=order,
        )
        
        self._store.store_transform(transform)
        return transform
    
    def get_transform(self, transform_id: str) -> Optional[DataTransformation]:
        """Get transform by ID."""
        return self._store.get_transform(transform_id)
    
    def list_transforms(self) -> List[DataTransformation]:
        """List all transformations."""
        return self._store.get_all_transforms()
    
    def apply_transform(
        self,
        transform: DataTransformation,
        data: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Apply transformation to data."""
        logger.info(f"Applying {transform.transform_type.value} transformation")
        
        if transform.transform_type == TransformType.MAP:
            return self._apply_map(data, transform.config)
        elif transform.transform_type == TransformType.FILTER:
            return self._apply_filter(data, transform.config)
        elif transform.transform_type == TransformType.AGGREGATE:
            return self._apply_aggregate(data, transform.config)
        elif transform.transform_type == TransformType.DEDUP:
            return self._apply_dedup(data, transform.config)
        else:
            return data
    
    def _apply_map(
        self,
        data: List[Dict[str, Any]],
        config: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Apply map transformation (field mapping)."""
        field_mappings = config.get("field_mappings", {})
        computed_fields = config.get("computed_fields", {})
        
        result = []
        for record in data:
            new_record = {}
            
            # Apply field mappings
            for old_field, new_field in field_mappings.items():
                if old_field in record:
                    new_record[new_field] = record[old_field]
            
            # Copy unmapped fields
            for key, value in record.items():
                if key not in field_mappings:
                    new_record[key] = value
            
            # Add computed fields
            for field, formula in computed_fields.items():
                new_record[field] = self._compute_value(formula, new_record)
            
            result.append(new_record)
        
        return result
    
    def _apply_filter(
        self,
        data: List[Dict[str, Any]],
        config: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Apply filter transformation."""
        conditions = config.get("conditions", [])
        
        result = []
        for record in data:
            if self._evaluate_conditions(record, conditions):
                result.append(record)
        
        return result
    
    def _apply_aggregate(
        self,
        data: List[Dict[str, Any]],
        config: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Apply aggregation transformation."""
        group_by = config.get("group_by", [])
        aggregations = config.get("aggregations", {})
        
        groups: Dict[tuple, List[Dict[str, Any]]] = {}
        
        for record in data:
            key = tuple(record.get(f, None) for f in group_by)
            if key not in groups:
                groups[key] = []
            groups[key].append(record)
        
        result = []
        for key, group_data in groups.items():
            agg_record = dict(zip(group_by, key))
            
            for field, agg_func in aggregations.items():
                values = [r.get(field, 0) for r in group_data]
                
                if agg_func == "sum":
                    agg_record[field] = sum(values)
                elif agg_func == "avg":
                    agg_record[field] = sum(values) / len(values) if values else 0
                elif agg_func == "count":
                    agg_record[field] = len(values)
                elif agg_func == "min":
                    agg_record[field] = min(values) if values else 0
                elif agg_func == "max":
                    agg_record[field] = max(values) if values else 0
            
            result.append(agg_record)
        
        return result
    
    def _apply_dedup(
        self,
        data: List[Dict[str, Any]],
        config: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Apply deduplication transformation."""
        dedup_fields = config.get("dedup_fields", [])
        keep = config.get("keep", "first")  # first or last
        
        seen: Dict[tuple, Any] = {}
        result = []
        
        for record in data:
            key = tuple(record.get(f, None) for f in dedup_fields)
            
            if key not in seen:
                seen[key] = record
                result.append(record)
            elif keep == "last":
                seen[key] = record
        
        if keep == "last":
            result = list(seen.values())
        
        return result
    
    # Operators permitted in formula expressions.
    _SAFE_OPS: Dict[type, Any] = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
    }

    def _safe_eval_expr(self, node: ast.expr, names: Dict[str, float]) -> float:
        """Recursively evaluate a safe arithmetic AST node.

        Only numeric literals, whitelisted binary/unary operators, and
        pre-resolved field-name constants are allowed.  ``ast.Pow`` and all
        other node types are intentionally excluded to prevent arithmetic DoS
        (e.g. ``9**9**9``).
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return float(node.value)
        if isinstance(node, ast.Name):
            if node.id not in names:
                raise ValueError(f"Unknown name '{node.id}' in formula")
            return float(names[node.id])
        if isinstance(node, ast.BinOp) and type(node.op) in self._SAFE_OPS:
            left = self._safe_eval_expr(node.left, names)
            right = self._safe_eval_expr(node.right, names)
            op_fn = self._SAFE_OPS[type(node.op)]
            if isinstance(node.op, ast.Div) and right == 0.0:
                raise ZeroDivisionError("Division by zero in formula")
            return op_fn(left, right)
        if isinstance(node, ast.UnaryOp) and type(node.op) in self._SAFE_OPS:
            operand = self._safe_eval_expr(node.operand, names)
            return self._SAFE_OPS[type(node.op)](operand)
        raise ValueError(f"Unsupported expression type: {type(node).__name__}")

    def _compute_value(self, formula: str, record: Dict[str, Any]) -> float:
        """Compute a numeric value from a formula string using a safe AST evaluator.

        Variable names in the formula are resolved against numeric fields in
        *record*.  Only the four basic arithmetic operators (+, -, *, /) and
        unary +/- are permitted.  ``**`` (power) and all other constructs are
        rejected to prevent arithmetic DoS attacks.
        """
        if not formula or not formula.strip():
            return 0.0
        if len(formula) > 256:
            logger.warning("Formula exceeds maximum length (256 chars), skipping evaluation")
            return 0.0
        try:
            names = {k: float(v) for k, v in record.items() if isinstance(v, (int, float))}
            tree = ast.parse(formula.strip(), mode="eval")
            return self._safe_eval_expr(tree.body, names)
        except Exception as exc:
            logger.debug("Formula evaluation failed for %r: %s", formula, exc)
            return 0.0
    
    def _evaluate_conditions(
        self,
        record: Dict[str, Any],
        conditions: List[Dict[str, Any]],
    ) -> bool:
        """Evaluate filter conditions."""
        if not conditions:
            return True
        
        for condition in conditions:
            field = condition.get("field")
            operator = condition.get("operator")
            value = condition.get("value")
            
            record_value = record.get(field)
            
            if operator == "eq" and record_value != value:
                return False
            elif operator == "ne" and record_value == value:
                return False
            elif operator == "gt" and record_value <= value:
                return False
            elif operator == "gte" and record_value < value:
                return False
            elif operator == "lt" and record_value >= value:
                return False
            elif operator == "lte" and record_value > value:
                return False
        
        return True


# Global singleton
_data_transformer: Optional[DataTransformer] = None


def get_data_transformer(store: Optional[PipelineStore] = None) -> DataTransformer:
    """Get or create the singleton DataTransformer instance."""
    global _data_transformer
    
    if _data_transformer is None:
        _data_transformer = DataTransformer(store=store)
    return _data_transformer