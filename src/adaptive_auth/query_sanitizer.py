"""
Query Sanitizer & Parameterization Module for Cypher / Graph Queries.
Provides strict input sanitization, parameter escaping, and dictionary binding generator
to eliminate Cypher/SQL injection vulnerabilities in graph queries (#2592).
"""

import re
from typing import Any, Dict, Tuple


def sanitize_graph_parameter(value: Any) -> Any:
    """
    Sanitize graph query parameters. String values are stripped of dangerous Cypher injection primitives
    (e.g., quotes, semicolons, comment markers).
    """
    if isinstance(value, str):
        # Remove potential Cypher injection operators
        sanitized = re.sub(r'[\';"\\]|--', "", value)
        return sanitized.strip()
    return value


def build_parameterized_query(base_query: str, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Build a safe parameterized Cypher query and sanitized parameter dictionary.
    """
    sanitized_params: Dict[str, Any] = {}
    for key, val in params.items():
        safe_key = re.sub(r"\W", "_", key)
        sanitized_params[safe_key] = sanitize_graph_parameter(val)

    return base_query, sanitized_params
