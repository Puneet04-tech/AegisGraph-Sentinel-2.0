"""Render the Risk Analytics page with several alerts.

Regression guard: the alert-card block used a module-level
``html = f\"\"\"...\"\"\"``, which shadowed the imported ``html`` module. The first
card rendered, then ``_escape_network_tooltip_value()`` called
``"<div...>".escape(...)`` on the second card and the page died with
``AttributeError: 'str' object has no attribute 'escape'``. One alert hid the
bug; two or more always exposed it.
"""

from __future__ import annotations

import os

import pandas as pd
import pytest

StreamlitAppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")
PAGE = "📊 Risk Analytics"


def _alert(index: int, severity: str, title: str | None = None) -> dict:
    return {
        "id": f"AL-90{index}",
        "time": pd.Timestamp.now(),
        "severity": severity,
        "title": title or f"Test alert {index}",
        "category": "Graph",
        "lat": 0.0,
        "lon": 0.0,
        "status": "Active",
    }


def _render_risk_analytics(monkeypatch, alerts):
    """Render the page without a backend: session pre-authenticated, API unreachable."""
    monkeypatch.setenv("API_URL", "http://127.0.0.1:9")
    at = StreamlitAppTest.from_file(APP_PATH, default_timeout=90)
    at.session_state["logged_in"] = True
    at.session_state["api_key"] = "test-key"
    at.session_state["role"] = "admin"
    at.session_state["realtime_alerts"] = alerts
    at.run()
    at.sidebar.radio[0].set_value(PAGE).run()
    return at


def _markdown(at) -> str:
    return " ".join(str(block.value) for block in at.main.get("markdown"))


def test_risk_analytics_renders_every_alert_card(monkeypatch):
    at = _render_risk_analytics(
        monkeypatch,
        [_alert(1, "Critical"), _alert(2, "High"), _alert(3, "Medium")],
    )

    assert not at.exception, [exception.value for exception in at.exception]

    markdown = _markdown(at)
    assert markdown.count('class="alert-card"') == 3
    for alert_id in ("AL-901", "AL-902", "AL-903"):
        assert alert_id in markdown


def test_alert_values_are_escaped_into_the_card(monkeypatch):
    at = _render_risk_analytics(
        monkeypatch,
        [
            _alert(1, "Critical", title='<img src=x onerror="alert(1)">'),
            _alert(2, "High", title='Tom & Jerry "quoted"'),
        ],
    )

    assert not at.exception, [exception.value for exception in at.exception]

    markdown = _markdown(at)
    assert markdown.count('class="alert-card"') == 2
    # The HTML module is still a module: alert text is escaped, never injected.
    assert "&lt;img src=x" in markdown
    assert "<img src=x" not in markdown
    assert "Tom &amp; Jerry &quot;quoted&quot;" in markdown
