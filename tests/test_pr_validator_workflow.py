"""Regression coverage for PR validator workflow gating."""

from pathlib import Path


def test_pr_validator_skips_screenshot_gate_for_backend_only_changes():
    source = Path(".github/workflows/pr-validator.yml").read_text(encoding="utf-8")

    assert "Detect Backend-Only Change Set" in source
    assert "backend_only" in source
    assert "backend or infrastructure only" in source
