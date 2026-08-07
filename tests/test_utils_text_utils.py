"""Tests for src.utils.text_utils."""

import pytest

from src.utils.text_utils import (
    camel_to_snake,
    mask,
    normalize_whitespace,
    sanitize_log_message,
    slugify,
    split_csv_line,
    truncate,
)


class TestSlugify:
    def test_basic(self):
        assert slugify("Hello World") == "hello-world"

    def test_collapses_multiple_hyphens(self):
        assert slugify("a  b--c  d") == "a-b-c-d"

    def test_strips_leading_and_trailing_hyphens(self):
        assert slugify("-Hello- World-") == "hello-world"

    def test_non_alphanumerics(self):
        assert slugify("Risk Score 42!") == "risk-score-42"

    def test_underscores_become_hyphens(self):
        assert slugify("transaction_id") == "transaction-id"

    def test_keeps_digits(self):
        assert slugify("muleAccount123") == "muleaccount123"

    def test_empty_string(self):
        assert slugify("") == ""

    def test_only_symbols(self):
        assert slugify("!!! *** ###") == ""

    def test_none(self):
        assert slugify(None) == ""

    def test_non_string_input(self):
        assert slugify(12345) == "12345"

    def test_unicode_diacritics_stripped(self):
        assert slugify("héllo wörld") == "hello-world"

    def test_multi_byte_unicode_removed(self):
        assert slugify("转账账户 用户") == ""


class TestTruncate:
    def test_shorter_than_limit_returned_as_is(self):
        assert truncate("short", 10) == "short"

    def test_exact_length_returned_as_is(self):
        assert truncate("12345", 5) == "12345"

    def test_truncates_with_default_suffix(self):
        assert truncate("0123456789", 5) == "01..."

    def test_includes_suffix_in_length(self):
        result = truncate("0123456789", 5)
        assert len(result) == 5
        assert result.endswith("...")

    def test_custom_suffix(self):
        assert truncate("0123456789", 6, suffix="..") == "0123.."

    def test_empty_suffix(self):
        assert truncate("0123456789", 3, suffix="") == "012"

    def test_suffix_longer_than_max_length(self):
        assert truncate("0123456789", 2, suffix="...") == ".."

    def test_zero_max_length(self):
        assert truncate("anything", 0) == ""

    def test_negative_max_length(self):
        assert truncate("anything", -3) == ""

    def test_empty_string(self):
        assert truncate("", 5) == ""

    def test_none(self):
        assert truncate(None, 5) == ""

    def test_non_string_input(self):
        assert truncate(123456789, 4) == "1..."

    def test_multi_byte_unicode_counts_as_characters(self):
        assert truncate("café奶油", 4) == "c..."


class TestMask:
    def test_example(self):
        assert mask("1234567890", 4) == "1234**7890"

    def test_default_visible(self):
        assert mask("1234567890") == "1234**7890"

    def test_shorter_than_two_visible_unchanged(self):
        assert mask("abcdef", 4) == "abcdef"

    def test_equal_to_two_visible_unchanged(self):
        assert mask("12345678", 4) == "12345678"

    def test_custom_mask_char(self):
        assert mask("1234567890", 3, mask_char="X") == "123XXXX890"

    def test_zero_visible_masks_everything(self):
        assert mask("123456", 0) == "******"

    def test_negative_visible_treated_as_zero(self):
        assert mask("123456", -2) == "******"

    def test_none(self):
        assert mask(None) == ""

    def test_non_string_input(self):
        assert mask(12345678, 3) == "123**678"

    def test_multi_byte_unicode(self):
        assert mask("账户转账测试", 2) == "账户**测试"


class TestNormalizeWhitespace:
    def test_collapses_runs(self):
        assert normalize_whitespace("a    b   c") == "a b c"

    def test_strips_edges(self):
        assert normalize_whitespace("   hello world   ") == "hello world"

    def test_mixed_whitespace_types(self):
        assert normalize_whitespace("a\t\tb\n\nc\rd") == "a b c d"

    def test_empty_string(self):
        assert normalize_whitespace("") == ""

    def test_only_whitespace(self):
        assert normalize_whitespace(" \t\n ") == ""

    def test_none(self):
        assert normalize_whitespace(None) == ""

    def test_non_string_input(self):
        assert normalize_whitespace(42) == "42"

    def test_no_whitespace_unchanged(self):
        assert normalize_whitespace("fraud-alert") == "fraud-alert"


class TestSplitCsvLine:
    def test_simple_line(self):
        assert split_csv_line("a,b,c") == ["a", "b", "c"]

    def test_embedded_comma_in_quotes(self):
        assert split_csv_line('"a,b",c') == ["a,b", "c"]

    def test_escaped_double_quote(self):
        assert split_csv_line('"say ""hi""",x') == ['say "hi"', "x"]

    def test_empty_fields(self):
        assert split_csv_line("a,,c") == ["a", "", "c"]

    def test_trailing_comma(self):
        assert split_csv_line("a,") == ["a", ""]

    def test_leading_comma(self):
        assert split_csv_line(",a") == ["", "a"]

    def test_single_field(self):
        assert split_csv_line("only") == ["only"]

    def test_quoted_field_with_spaces(self):
        assert split_csv_line('" padded ",x') == [" padded ", "x"]

    def test_all_quoted(self):
        assert split_csv_line('"a","b,c","d"') == ["a", "b,c", "d"]

    def test_empty_string(self):
        assert split_csv_line("") == [""]

    def test_none(self):
        assert split_csv_line(None) == []

    def test_non_string_input(self):
        assert split_csv_line(123) == ["123"]


class TestCamelToSnake:
    def test_camel_case(self):
        assert camel_to_snake("camelCase") == "camel_case"

    def test_pascal_case(self):
        assert camel_to_snake("PascalCase") == "pascal_case"

    def test_acronym_then_word(self):
        assert camel_to_snake("HTGNNModel") == "htgnn_model"

    def test_acronym_only(self):
        assert camel_to_snake("HTGNN") == "htgnn"

    def test_digits_boundary(self):
        assert camel_to_snake("riskScore2Factor") == "risk_score2_factor"

    def test_already_snake_case(self):
        assert camel_to_snake("already_snake") == "already_snake"

    def test_single_word(self):
        assert camel_to_snake("word") == "word"

    def test_leading_capital_single_word(self):
        assert camel_to_snake("Word") == "word"

    def test_empty_string(self):
        assert camel_to_snake("") == ""

    def test_none(self):
        assert camel_to_snake(None) == ""


class TestSanitizeLogMessage:
    def test_ansi_color_codes_removed(self):
        assert sanitize_log_message("\x1b[31mred\x1b[0m") == "red"

    def test_ansi_with_bright_and_styles(self):
        assert sanitize_log_message("\x1b[1;32mok\x1b[m") == "ok"

    def test_ansi_osc_sequence_removed(self):
        assert sanitize_log_message("\x1b]0;title\x07body") == "body"

    def test_control_characters_removed(self):
        assert sanitize_log_message("a\x00b\x1fc") == "abc"

    def test_newline_and_tab_removed(self):
        assert sanitize_log_message("line\nbreak\ttext") == "linebreaktext"

    def test_clean_message_unchanged(self):
        assert sanitize_log_message("plain message") == "plain message"

    def test_del_removed(self):
        assert sanitize_log_message("a\x7fb") == "ab"

    def test_none(self):
        assert sanitize_log_message(None) == ""

    def test_non_string_input(self):
        assert sanitize_log_message(123) == "123"

    def test_empty_string(self):
        assert sanitize_log_message("") == ""
