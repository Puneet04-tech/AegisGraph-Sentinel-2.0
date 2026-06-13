"""
Stream Processor Module.

Real-time event processing, windowing, and transformation.
"""

import ast
import operator
import random
import threading
from threading import Lock
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timezone, timedelta
import logging

from .models import (
    StreamEvent,
    StreamWindow,
    StreamAggregation,
    WindowType,
    EventPriority,
)
from .store import StreamStore, get_stream_store

logger = logging.getLogger(__name__)


class StreamProcessor:
    """Stream Processor for real-time event processing.
    
    Provides:
        - Event ingestion
        - Windowing operations
        - Event transformation
        - Aggregation computation
    """
    
    def __init__(self, store: Optional[StreamStore] = None):
        """Initialize the stream processor."""
        self._store = store or get_stream_store()
        self._module_id = "stream_processor"
        self._handlers: Dict[str, List[Callable]] = {}
    
    def ingest_event(
        self,
        stream_name: str,
        event_type: str,
        source: str,
        payload: Dict[str, Any],
        priority: EventPriority = EventPriority.MEDIUM,
    ) -> StreamEvent:
        """Ingest an event into a stream."""
        logger.info(f"Ingesting event to {stream_name}: {event_type}")
        
        event = StreamEvent(
            event_type=event_type,
            source=source,
            payload=payload,
            priority=priority,
        )
        
        self._store.add_event(stream_name, event)
        
        # Trigger handlers
        self._trigger_handlers(stream_name, event)
        
        return event
    
    def register_handler(self, stream_name: str, handler: Callable) -> None:
        """Register an event handler."""
        if stream_name not in self._handlers:
            self._handlers[stream_name] = []
        self._handlers[stream_name].append(handler)
    
    def _trigger_handlers(self, stream_name: str, event: StreamEvent) -> None:
        """Trigger registered handlers."""
        handlers = self._handlers.get(stream_name, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Handler error: {e}")
    
    def create_window(
        self,
        name: str,
        window_type: WindowType,
        size_seconds: int,
        slide_seconds: int = None,
        session_timeout: int = None,
    ) -> StreamWindow:
        """Create a stream window."""
        logger.info(f"Creating window: {name}")
        
        window = StreamWindow(
            name=name,
            window_type=window_type,
            size_seconds=size_seconds,
            slide_seconds=slide_seconds,
            session_timeout=session_timeout,
        )
        
        self._store.store_window(window)
        return window
    
    def compute_aggregation(
        self,
        stream_name: str,
        window_id: str,
        metric_name: str,
        aggregation_type: str,
    ) -> StreamAggregation:
        """Compute stream aggregation."""
        logger.info(f"Computing {aggregation_type} for {metric_name} on {stream_name}")
        
        events = self._store.get_stream_events(stream_name, limit=1000)
        
        if not events:
            value = 0.0
        else:
            values = [e.payload.get(metric_name, 0) for e in events]
            values = [v for v in values if isinstance(v, (int, float))]
            
            if aggregation_type == "SUM":
                value = sum(values)
            elif aggregation_type == "AVG":
                value = sum(values) / len(values) if values else 0
            elif aggregation_type == "COUNT":
                value = len(values)
            elif aggregation_type == "MIN":
                value = min(values) if values else 0
            elif aggregation_type == "MAX":
                value = max(values) if values else 0
            else:
                value = sum(values) / len(values) if values else 0
        
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self._store.get_window(window_id).size_seconds if self._store.get_window(window_id) else 60)
        
        aggregation = StreamAggregation(
            stream_name=stream_name,
            window_id=window_id,
            metric_name=metric_name,
            aggregation_type=aggregation_type,
            value=value,
            window_start=window_start,
            window_end=now,
        )
        
        self._store.store_aggregation(aggregation)
        return aggregation
    
    def transform_event(
        self,
        event: StreamEvent,
        transformations: List[Dict[str, Any]],
    ) -> StreamEvent:
        """Transform an event."""
        for transform in transformations:
            transform_type = transform.get("type")
            
            if transform_type == "add_field":
                event.payload[transform["field"]] = transform["value"]
            elif transform_type == "rename_field":
                if transform["old_field"] in event.payload:
                    event.payload[transform["new_field"]] = event.payload.pop(transform["old_field"])
            elif transform_type == "compute":
                field = transform["field"]
                formula = transform["formula"]
                event.payload[field] = self._evaluate_formula(formula, event.payload)
        
        return event
    
    # Permitted arithmetic operators for formula evaluation.
    _SAFE_OPS: Dict[type, Any] = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
    }

    def _safe_eval_node(self, node: ast.expr, names: Dict[str, float]) -> float:
        """Recursively evaluate a safe arithmetic AST node.

        Intentionally excludes ``ast.Pow`` to prevent arithmetic DoS
        (e.g. ``9**9**9``).  Only numeric literals, field name references, and
        the four basic arithmetic operators are permitted.
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return float(node.value)
        if isinstance(node, ast.Name):
            if node.id not in names:
                raise ValueError(f"Unknown name '{node.id}' in formula")
            return float(names[node.id])
        if isinstance(node, ast.BinOp) and type(node.op) in self._SAFE_OPS:
            left = self._safe_eval_node(node.left, names)
            right = self._safe_eval_node(node.right, names)
            if isinstance(node.op, ast.Div) and right == 0.0:
                raise ZeroDivisionError("Division by zero in formula")
            return self._SAFE_OPS[type(node.op)](left, right)
        if isinstance(node, ast.UnaryOp) and type(node.op) in self._SAFE_OPS:
            return self._SAFE_OPS[type(node.op)](self._safe_eval_node(node.operand, names))
        raise ValueError(f"Unsupported expression type: {type(node).__name__}")

    def _evaluate_formula(self, formula: str, payload: Dict[str, Any]) -> float:
        """Evaluate a formula string against event payload fields using a safe AST evaluator.

        Supports +, -, *, / and numeric literals.  ``**`` (power) and all
        other constructs are rejected to prevent arithmetic DoS attacks.
        """
        if not formula or not formula.strip():
            return 0.0
        if len(formula) > 256:
            logger.warning("Formula exceeds maximum length (256 chars), skipping evaluation")
            return 0.0
        try:
            names = {k: float(v) for k, v in payload.items() if isinstance(v, (int, float))}
            tree = ast.parse(formula.strip(), mode="eval")
            return self._safe_eval_node(tree.body, names)
        except Exception as exc:
            logger.debug("Formula evaluation failed for %r: %s", formula, exc)
            return 0.0
    
    def get_stream_summary(self, stream_name: str) -> Dict[str, Any]:
        """Get stream summary."""
        events = self._store.get_stream_events(stream_name, limit=100)
        
        return {
            "stream_name": stream_name,
            "total_events": self._store.get_stream_count(stream_name),
            "recent_events": len(events),
            "event_types": list(set(e.event_type for e in events)),
            "sources": list(set(e.source for e in events)),
        }


# Global singleton
_stream_processor: Optional[StreamProcessor] = None
_stream_processor_lock = Lock()


def get_stream_processor(store: Optional[StreamStore] = None) -> StreamProcessor:
    """Get or create the singleton StreamProcessor instance."""
    global _stream_processor
    
    with _stream_processor_lock:
        if _stream_processor is None:
            _stream_processor = StreamProcessor(store=store)
        return _stream_processor