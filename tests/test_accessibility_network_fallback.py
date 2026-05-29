"""Regression coverage for accessible network explorer fallback."""

from pathlib import Path


def test_network_explorer_includes_structured_fallback():
    source = Path("app.py").read_text(encoding="utf-8")

    assert "Accessible Topology Summary" in source
    assert "st.dataframe(" in source
    assert "node_weight" in source
    assert "screen readers and keyboard-only review" in source
