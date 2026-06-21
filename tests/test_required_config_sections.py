import pytest

from src.utils.helpers import (
    validate_required_sections,
    REQUIRED_CONFIG_SECTIONS,
)


def _full_config():
    """A config containing every required top-level section."""
    return {section: {} for section in REQUIRED_CONFIG_SECTIONS}


def test_all_required_sections_present_passes():
    assert validate_required_sections(_full_config()) == []


def test_missing_section_is_reported():
    config = _full_config()
    del config["model"]

    errors = validate_required_sections(config)

    assert len(errors) == 1
    assert "model" in errors[0]


def test_multiple_missing_sections_all_reported():
    config = _full_config()
    del config["model"]
    del config["database"]

    errors = validate_required_sections(config)

    assert len(errors) == 1
    assert "model" in errors[0]
    assert "database" in errors[0]


def test_empty_config_reports_missing():
    errors = validate_required_sections({})

    assert len(errors) > 0


def test_non_dict_config_is_rejected():
    errors = validate_required_sections(["not", "a", "dict"])

    assert len(errors) == 1
    assert "dict" in errors[0].lower()