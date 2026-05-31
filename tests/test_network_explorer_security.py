"""Regression coverage for network explorer HTML and script escaping."""

from pathlib import Path


def test_network_explorer_escapes_tooltip_values_before_inner_html():
    source = Path("app.py").read_text(encoding="utf-8")

    assert "node_html = _escape_network_tooltip_value(node)" in source
    assert "role_html = _escape_network_tooltip_value(role)" in source
    assert "source_html = _escape_network_tooltip_value(u)" in source
    assert "destination_html = _escape_network_tooltip_value(v)" in source
    assert "{node}</b><br/>" not in source
    assert "{role}<br/>" not in source
    assert "{u} ➡️ {v}" not in source


def test_network_explorer_json_encodes_search_value_for_inline_script():
    source = Path("app.py").read_text(encoding="utf-8")

    assert "search_json = _json_for_inline_script(search_val or None)" in source
    assert "var searchId = {search_json};" in source
    assert 'var searchId = "{search_val}";' not in source
    assert 'searchId !== "None"' not in source
