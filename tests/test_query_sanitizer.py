import pytest
from src.adaptive_auth.query_sanitizer import (
    sanitize_graph_parameter,
    build_parameterized_query,
)


def test_sanitize_graph_parameter_cleans_dangerous_characters():
    malicious_input = "user_id' OR 1=1; --"
    sanitized = sanitize_graph_parameter(malicious_input)
    assert "'" not in sanitized
    assert ";" not in sanitized
    assert "--" not in sanitized
    assert sanitized == "user_id OR 1=1"


def test_sanitize_graph_parameter_preserves_safe_types():
    assert sanitize_graph_parameter(12345) == 12345
    assert sanitize_graph_parameter(True) is True
    assert sanitize_graph_parameter(None) is None


def test_build_parameterized_query():
    query = "MATCH (u:User {id: $user_id}) RETURN u"
    params = {"user_id": "admin'; DROP GRAPH;--", "tenant_id": 42}

    clean_query, clean_params = build_parameterized_query(query, params)
    assert clean_query == query
    assert clean_params["user_id"] == "admin DROP GRAPH"
    assert clean_params["tenant_id"] == 42
