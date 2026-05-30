"""Regression coverage for semantic alert markup."""

from pathlib import Path


def test_alert_cards_include_aria_semantics():
    source = Path("app.py").read_text(encoding="utf-8")

    assert 'role="article"' in source
    assert 'aria-label="{aria_label}"' in source
    assert 'role="status" aria-live="polite"' in source
