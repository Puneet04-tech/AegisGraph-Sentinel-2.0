"""Regression coverage for accessible network explorer fallback."""

from pathlib import Path


def test_network_explorer_includes_structured_fallback():
    source = Path("app.py").read_text(encoding="utf-8")

    # Verify overall header and screen-reader container presence
    assert "Accessible Topology Summary" in source
    assert "accessible-fallback" in source
    assert "aria-label='Accessible Network Topology Summary'" in source

    # Verify presence of semantic HTML table and structures
    assert "fallback-table" in source
    assert "<thead>" in source
    assert "<tbody>" in source
    assert "<tr>" in source
    assert "<th>" in source
    assert "<td>" in source

    # Verify that screen reader helper attributes exist
    assert "position:absolute; width:1px; height:1px" in source

    # Verify that dynamic prop step routing and details exist
    assert "phase_descriptions" in source
    assert "fallback_nodes" in source
    assert "fallback_edges" in source
    assert "search_query" in source
    assert "animate_propagation" in source

    # Verify we did not use st.dataframe for the fallback
    assert "st.dataframe(fallback_rows" not in source
