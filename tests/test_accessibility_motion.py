"""Regression coverage for reduced-motion dashboard styling."""

from pathlib import Path


def test_dashboard_motion_styles_respect_reduced_motion():
    source = Path("app.py").read_text(encoding="utf-8")

    assert "@media (prefers-reduced-motion: no-preference)" in source
    assert "animation: slideIn 0.3s ease-out forwards;" in source
    assert "animation: pulse 2s infinite;" in source
