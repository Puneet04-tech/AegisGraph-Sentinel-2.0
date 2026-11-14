"""Every Streamlit page must render without raising.

The Risk Analytics crash (a module-level ``html`` assignment shadowing the
``html`` module) showed that a page-level bug can hide behind a healthy-looking
sidebar. These tests open each page in Streamlit's headless harness and fail on
any exception, so a broken page cannot ship unnoticed.

Rendering is hermetic: the session is pre-authenticated so the login callback
never runs, and ``API_URL`` points at a closed port so backend calls fail fast
instead of depending on a running API.
"""

from __future__ import annotations

import os

import pytest

StreamlitAppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")

# ASCII ids keep pytest's terminal output safe on Windows consoles that cannot
# encode emoji; the labels are what the app's radio widget actually matches.
PAGES = {
    "command-center": "🧭 Command Center",
    "transaction-scan": "💳 Transaction Scan",
    "batch-triage": "📁 Batch Triage",
    "risk-analytics": "📊 Risk Analytics",
    "graph-explorer": "🕸️ Network Graph Explorer",
    "behavioral-biometrics": "⌨️ Behavioral Biometrics",
    "innovation-lab": "🧪 Innovation Lab",
    "system-brief": "ℹ️ System Brief",
}


def _render(page_label: str, monkeypatch) -> object:
    monkeypatch.setenv("API_URL", "http://127.0.0.1:9")
    at = StreamlitAppTest.from_file(APP_PATH, default_timeout=90)
    at.session_state["logged_in"] = True
    at.session_state["api_key"] = "test-key"
    at.session_state["role"] = "admin"
    at.run()
    at.sidebar.radio[0].set_value(page_label).run()
    return at


@pytest.mark.parametrize("page_name", list(PAGES), ids=list(PAGES))
def test_every_page_renders_without_exception(page_name, monkeypatch):
    at = _render(PAGES[page_name], monkeypatch)

    assert not at.exception, [str(exception.value) for exception in at.exception]
    markdown = [str(block.value).strip() for block in at.main.get("markdown")]
    assert any(markdown), f"{page_name} rendered no content"


def test_pages_are_reachable_from_the_navigation(monkeypatch):
    """The sidebar must offer every page the app can render."""
    at = _render(PAGES["command-center"], monkeypatch)

    offered = {option for option in at.sidebar.radio[0].options}
    assert set(PAGES.values()) <= offered
