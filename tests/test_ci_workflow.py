"""Regression coverage for CI matrix partitioning."""

from pathlib import Path


def test_ci_workflow_runs_coverage_on_one_matrix_leg():
    source = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "run_coverage: true" in source
    assert "RUN_COVERAGE" in source
    assert "python -m pytest tests/ --cov=src --cov-report=term-missing" in source
    assert "python -m pytest tests/" in source
