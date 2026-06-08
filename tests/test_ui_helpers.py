"""Unit tests for src/ui/helpers.py.

These tests cover all pure-Python helper utilities extracted from app.py.
They run without Streamlit, PyTorch, NetworkX, or any other heavy dependency.

Extracted as part of the modularisation effort described in issue #854:
app.py (4007 lines) had zero unit tests.  This file begins building coverage
for the portions of the frontend that contain independently testable logic.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import pytest

from src.ui.helpers import (
    REQUIRED_CSV_COLUMNS,
    accessible_status,
    classify_decision,
    escape_network_tooltip_value,
    get_api_timestamp,
    json_for_inline_script,
    validate_csv_columns,
)


# ─────────────────────────────────────────────────────────────────────────────
# classify_decision
# ─────────────────────────────────────────────────────────────────────────────

class TestClassifyDecision:
    """Tests for the pure-Python core of the decision badge renderer."""

    @pytest.mark.parametrize("decision", ["SAFE", "ALLOW", "APPROVE", "safe", "allow", "Approve"])
    def test_safe_allow_approve_map_to_success(self, decision: str) -> None:
        severity, emoji, label = classify_decision(decision)
        assert severity == "success", f"Expected 'success' for {decision!r}, got {severity!r}"
        assert emoji == "✅"
        assert label == decision.upper()

    def test_review_maps_to_warning(self) -> None:
        severity, emoji, label = classify_decision("REVIEW")
        assert severity == "warning"
        assert emoji == "⚠️"
        assert label == "REVIEW"

    def test_review_case_insensitive(self) -> None:
        severity, _, _ = classify_decision("review")
        assert severity == "warning"

    def test_block_maps_to_error(self) -> None:
        severity, emoji, label = classify_decision("BLOCK")
        assert severity == "error"
        assert emoji == "🛑"
        assert label == "BLOCK"

    def test_block_case_insensitive(self) -> None:
        severity, _, _ = classify_decision("block")
        assert severity == "error"

    def test_unknown_decision_maps_to_info(self) -> None:
        severity, emoji, label = classify_decision("UNKNOWN_STATUS")
        assert severity == "info"
        assert emoji == "ℹ️"
        assert label == "UNKNOWN_STATUS"

    def test_empty_string_does_not_raise(self) -> None:
        severity, _, label = classify_decision("")
        assert severity == "info"
        assert label == ""

    def test_numeric_decision_does_not_raise(self) -> None:
        """Non-string inputs are cast to string; must not raise."""
        severity, _, label = classify_decision(42)  # type: ignore[arg-type]
        assert severity == "info"
        assert label == "42"

    def test_returns_three_tuple(self) -> None:
        result = classify_decision("ALLOW")
        assert len(result) == 3, "classify_decision must return a 3-tuple"


# ─────────────────────────────────────────────────────────────────────────────
# get_api_timestamp
# ─────────────────────────────────────────────────────────────────────────────

class TestGetApiTimestamp:
    """Tests for the ISO 8601 UTC timestamp generator."""

    _ISO_8601_UTC_PATTERN = re.compile(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
    )

    def test_returns_iso_8601_format(self) -> None:
        ts = get_api_timestamp()
        assert self._ISO_8601_UTC_PATTERN.match(ts), (
            f"Timestamp {ts!r} does not match YYYY-MM-DDTHH:MM:SSZ"
        )

    def test_ends_with_z_suffix(self) -> None:
        """API schemas require the Z suffix, not +00:00."""
        ts = get_api_timestamp()
        assert ts.endswith("Z"), f"Expected Z suffix, got {ts!r}"

    def test_is_parseable_as_utc_datetime(self) -> None:
        ts = get_api_timestamp()
        parsed = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        diff_seconds = abs((now - parsed).total_seconds())
        assert diff_seconds < 5, (
            f"Timestamp {ts!r} is more than 5 seconds away from now"
        )

    def test_successive_calls_are_non_decreasing(self) -> None:
        ts1 = get_api_timestamp()
        ts2 = get_api_timestamp()
        # String comparison works because the format is lexicographically ordered.
        assert ts2 >= ts1, "Successive timestamps must not go backwards"


# ─────────────────────────────────────────────────────────────────────────────
# accessible_status
# ─────────────────────────────────────────────────────────────────────────────

class TestAccessibleStatus:
    """Tests for the screen-reader-friendly status string builder."""

    def test_format_contains_emoji_and_label(self) -> None:
        result = accessible_status("✅", "Safe")
        assert "✅" in result
        assert "Safe" in result

    def test_plain_text_label_appears_twice(self) -> None:
        """Label must appear in both the visual and the parenthetical fallback."""
        result = accessible_status("✅", "Safe")
        assert result.count("Safe") == 2, (
            f"Label 'Safe' should appear twice in {result!r} for screen readers"
        )

    def test_format_structure(self) -> None:
        result = accessible_status("⚠️", "Review")
        assert result == "⚠️ Review (Review)"

    def test_empty_label(self) -> None:
        result = accessible_status("ℹ️", "")
        assert "ℹ️" in result


# ─────────────────────────────────────────────────────────────────────────────
# escape_network_tooltip_value
# ─────────────────────────────────────────────────────────────────────────────

class TestEscapeNetworkTooltipValue:
    """Tests for HTML-escaping of dynamic graph values."""

    def test_ampersand_is_escaped(self) -> None:
        assert escape_network_tooltip_value("AT&T") == "AT&amp;T"

    def test_less_than_greater_than_escaped(self) -> None:
        result = escape_network_tooltip_value("<script>")
        assert "<" not in result
        assert ">" not in result
        assert "&lt;" in result
        assert "&gt;" in result

    def test_double_quote_is_escaped(self) -> None:
        result = escape_network_tooltip_value('"value"')
        assert '"' not in result
        assert "&quot;" in result

    def test_plain_value_unchanged(self) -> None:
        assert escape_network_tooltip_value("ACC123456789") == "ACC123456789"

    def test_integer_input_does_not_raise(self) -> None:
        result = escape_network_tooltip_value(50000)
        assert result == "50000"

    def test_xss_payload_fully_escaped(self) -> None:
        payload = '<img src=x onerror="alert(1)">'
        result = escape_network_tooltip_value(payload)
        assert "<" not in result
        assert ">" not in result
        assert '"' not in result

    def test_none_input_does_not_raise(self) -> None:
        result = escape_network_tooltip_value(None)
        assert result == "None"


# ─────────────────────────────────────────────────────────────────────────────
# json_for_inline_script
# ─────────────────────────────────────────────────────────────────────────────

class TestJsonForInlineScript:
    """Tests for safe JSON serialisation for inline script injection."""

    def test_dict_serialised_correctly(self) -> None:
        result = json_for_inline_script({"key": "value", "count": 42})
        parsed = json.loads(result)
        assert parsed == {"key": "value", "count": 42}

    def test_list_serialised_correctly(self) -> None:
        result = json_for_inline_script([1, 2, 3])
        assert json.loads(result) == [1, 2, 3]

    def test_unicode_not_ascii_escaped(self) -> None:
        """Non-ASCII characters must be preserved, not \\uXXXX-escaped."""
        result = json_for_inline_script({"currency": "₹", "name": "मुंबई"})
        assert "₹" in result, "Rupee symbol should not be ASCII-escaped"
        assert "मुंबई" in result, "Hindi text should not be ASCII-escaped"

    def test_boolean_serialised_as_json_bool(self) -> None:
        assert json_for_inline_script(True) == "true"
        assert json_for_inline_script(False) == "false"

    def test_none_serialised_as_null(self) -> None:
        assert json_for_inline_script(None) == "null"

    def test_non_serialisable_raises_type_error(self) -> None:
        with pytest.raises(TypeError):
            json_for_inline_script(object())

    def test_output_is_valid_json(self) -> None:
        value = {"risk_score": 0.87, "decision": "BLOCK", "account": "ACC123"}
        result = json_for_inline_script(value)
        parsed = json.loads(result)
        assert parsed["risk_score"] == pytest.approx(0.87)


# ─────────────────────────────────────────────────────────────────────────────
# validate_csv_columns
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateCsvColumns:
    """Tests for CSV column validation used in batch transaction upload."""

    def test_all_required_columns_present_returns_empty(self) -> None:
        columns = {"transaction_id", "source_account", "target_account", "amount"}
        assert validate_csv_columns(columns) == []

    def test_extra_columns_do_not_cause_failure(self) -> None:
        columns = {"transaction_id", "source_account", "target_account", "amount",
                   "currency", "mode", "timestamp"}
        assert validate_csv_columns(columns) == []

    def test_single_missing_column_reported(self) -> None:
        columns = {"transaction_id", "source_account", "target_account"}
        missing = validate_csv_columns(columns)
        assert missing == ["amount"]

    def test_all_columns_missing_reports_all(self) -> None:
        missing = validate_csv_columns(set())
        assert set(missing) == REQUIRED_CSV_COLUMNS

    def test_result_is_sorted(self) -> None:
        """Missing column list must be sorted for deterministic error messages."""
        missing = validate_csv_columns(set())
        assert missing == sorted(missing)

    def test_required_csv_columns_constant(self) -> None:
        """Guard against accidental mutation of the REQUIRED_CSV_COLUMNS set."""
        assert "transaction_id" in REQUIRED_CSV_COLUMNS
        assert "source_account" in REQUIRED_CSV_COLUMNS
        assert "target_account" in REQUIRED_CSV_COLUMNS
        assert "amount" in REQUIRED_CSV_COLUMNS
        assert len(REQUIRED_CSV_COLUMNS) == 4
