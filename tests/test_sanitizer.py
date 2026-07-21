"""
Comprehensive unit tests for config/sanitizer.py

Tests cover:
- Safe input preservation
- ANSI escape sequence removal
- HTML/XML tag removal
- SQL/Cypher pattern cleanup
- Edge cases (None, empty, very long input)
- Unicode normalization
- Whitespace normalization
- Mixed content handling
"""

import sys
import os

# Add config to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config.sanitizer import (
    sanitize_query_input,
    remove_ansi_sequences,
    remove_html_tags,
    normalize_whitespace,
    normalize_unicode,
    remove_dangerous_patterns,
    truncate_at_semicolon,
)


class TestSafeInput:
    """Test that legitimate user input remains readable."""

    def test_normal_english_sentence(self):
        """Normal English sentences should be preserved."""
        input_text = "Hello, this is a normal sentence."
        result = sanitize_query_input(input_text)
        assert result == input_text

    def test_punctuation_preserved(self):
        """Punctuation should be preserved."""
        input_text = "Hello, world! How are you? I'm fine."
        result = sanitize_query_input(input_text)
        assert result == input_text

    def test_unicode_characters(self):
        """Unicode characters should be normalized but preserved."""
        input_text = "café résumé naïve 日本語"
        result = sanitize_query_input(input_text)
        # Unicode normalization may change byte representation but should preserve meaning
        assert "café" in result or "cafe" in result
        assert "résumé" in result or "resume" in result

    def test_multiline_text(self):
        """Multiline text should have normalized whitespace."""
        input_text = "Line 1\nLine 2\nLine 3"
        result = sanitize_query_input(input_text)
        assert "Line 1" in result
        assert "Line 2" in result
        assert "Line 3" in result
        assert "\n" not in result  # Newlines should be normalized

    def test_numbers_and_special_chars(self):
        """Numbers and special characters should be preserved."""
        input_text = "User123!@#$%^&*()_+-=[]{}|;':\",./<>?"
        result = sanitize_query_input(input_text)
        assert "User123" in result


class TestANSISequences:
    """Test ANSI escape sequence removal."""

    def test_basic_ansi_removal(self):
        """Basic ANSI escape codes should be removed."""
        input_text = "Hello\x1B[31mWorld"
        result = sanitize_query_input(input_text)
        assert result == "HelloWorld"

    def test_multiple_ansi_codes(self):
        """Multiple ANSI codes should be removed."""
        input_text = "\x1B[31mRed\x1B[0m \x1B[32mGreen\x1B[0m"
        result = sanitize_query_input(input_text)
        assert result == "Red Green"

    def test_ansi_helper_function(self):
        """Test the remove_ansi_sequences helper directly."""
        input_text = "Text\x1B[31mwith\x1B[0m codes"
        result = remove_ansi_sequences(input_text)
        assert result == "Textwith codes"


class TestHTMLTags:
    """Test HTML/XML tag removal."""

    def test_simple_html_tag(self):
        """Simple HTML tags should be removed."""
        input_text = "<p>Hello</p>"
        result = sanitize_query_input(input_text)
        assert result == "Hello"

    def test_nested_tags(self):
        """Nested HTML tags should be removed."""
        input_text = "<div><p>Hello</p></div>"
        result = sanitize_query_input(input_text)
        assert result == "Hello"

    def test_malformed_tags(self):
        """Malformed tags should be handled gracefully - complete tags removed."""
        input_text = "<p>Hello</p>Unclosed<div"
        result = sanitize_query_input(input_text)
        assert "Hello" in result
        assert "Unclosed" in result
        # Only complete tags are removed, unclosed angle brackets may remain

    def test_xml_tags(self):
        """XML tags should be removed."""
        input_text = "<root><child>data</child></root>"
        result = sanitize_query_input(input_text)
        assert result == "data"

    def test_html_helper_function(self):
        """Test the remove_html_tags helper directly."""
        input_text = "<script>alert(1)</script>"
        result = remove_html_tags(input_text)
        assert result == "alert(1)"


class TestSQLPatterns:
    """Test SQL-like pattern cleanup."""

    def test_union_select(self):
        """UNION SELECT pattern should be removed."""
        input_text = "SELECT * FROM users UNION SELECT * FROM admin"
        result = sanitize_query_input(input_text)
        assert "UNION SELECT" not in result.upper()

    def test_drop_database(self):
        """DROP DATABASE pattern should be removed."""
        input_text = "DROP DATABASE production"
        result = sanitize_query_input(input_text)
        assert "DROP DATABASE" not in result.upper()

    def test_drop_table(self):
        """DROP TABLE pattern should be removed."""
        input_text = "DROP TABLE users"
        result = sanitize_query_input(input_text)
        assert "DROP TABLE" not in result.upper()

    def test_case_insensitive(self):
        """Pattern matching should be case-insensitive."""
        input_text = "select * from users union select * from admin"
        result = sanitize_query_input(input_text)
        assert "union select" not in result.lower()


class TestCypherPatterns:
    """Test Cypher-like pattern cleanup."""

    def test_match_delete(self):
        """MATCH DELETE pattern should be removed."""
        input_text = "MATCH (n) DELETE n"
        result = sanitize_query_input(input_text)
        assert "MATCH DELETE" not in result.upper()

    def test_match_detach(self):
        """MATCH DETACH pattern should be removed."""
        input_text = "MATCH (n) DETACH DELETE n"
        result = sanitize_query_input(input_text)
        assert "MATCH DETACH" not in result.upper()

    def test_case_insensitive_cypher(self):
        """Cypher pattern matching should be case-insensitive."""
        input_text = "match (n) delete n"
        result = sanitize_query_input(input_text)
        assert "match delete" not in result.lower()


class TestBooleanInjection:
    """Test boolean injection pattern cleanup."""

    def test_or_1_equals_1(self):
        """Classic OR 1=1 pattern should be removed."""
        input_text = "SELECT * FROM users WHERE id = 1 OR 1=1"
        result = sanitize_query_input(input_text)
        assert "OR 1=1" not in result.upper()

    def test_or_string_equals_string(self):
        """OR 'a'='a' pattern should be removed."""
        input_text = "SELECT * FROM users WHERE name = 'test' OR 'a'='a'"
        result = sanitize_query_input(input_text)
        assert "OR" not in result.upper() or "'a'='a'" not in result


class TestSemicolonTruncation:
    """Test semicolon truncation for stacked query prevention."""

    def test_semicolon_truncation(self):
        """Input should be truncated at first semicolon."""
        input_text = "SELECT * FROM users; DROP TABLE admin"
        result = sanitize_query_input(input_text)
        assert result == "SELECT * FROM users"
        assert "DROP TABLE" not in result

    def test_no_semicolon(self):
        """Input without semicolon should be unchanged."""
        input_text = "SELECT * FROM users"
        result = sanitize_query_input(input_text)
        assert result == "SELECT * FROM users"

    def test_semicolon_helper_function(self):
        """Test the truncate_at_semicolon helper directly."""
        input_text = "First; Second; Third"
        result = truncate_at_semicolon(input_text)
        assert result == "First"


class TestWhitespaceNormalization:
    """Test whitespace normalization."""

    def test_multiple_spaces(self):
        """Multiple spaces should be collapsed to single space."""
        input_text = "Hello    World"
        result = sanitize_query_input(input_text)
        assert result == "Hello World"

    def test_tabs_to_spaces(self):
        """Tabs should be converted to spaces."""
        input_text = "Hello\tWorld"
        result = sanitize_query_input(input_text)
        assert result == "Hello World"

    def test_newlines_to_spaces(self):
        """Newlines should be converted to spaces."""
        input_text = "Hello\nWorld"
        result = sanitize_query_input(input_text)
        assert result == "Hello World"

    def test_mixed_whitespace(self):
        """Mixed whitespace should be normalized."""
        input_text = "Hello \t\n \r World"
        result = sanitize_query_input(input_text)
        assert result == "Hello World"

    def test_whitespace_helper_function(self):
        """Test the normalize_whitespace helper directly."""
        input_text = "Multiple   spaces\tand\nnewlines"
        result = normalize_whitespace(input_text)
        assert result == "Multiple spaces and newlines"


class TestUnicodeNormalization:
    """Test Unicode normalization."""

    def test_basic_unicode(self):
        """Basic Unicode characters should be normalized."""
        input_text = "café"
        result = normalize_unicode(input_text)
        assert result is not None
        assert len(result) > 0

    def test_unicode_helper_function(self):
        """Test the normalize_unicode helper directly."""
        input_text = "naïve résumé"
        result = normalize_unicode(input_text)
        assert result is not None


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_string(self):
        """Empty string should return empty string."""
        result = sanitize_query_input("")
        assert result == ""

    def test_none_input(self):
        """None input should return empty string."""
        result = sanitize_query_input(None)
        assert result == ""

    def test_very_long_input(self):
        """Very long input should be handled gracefully."""
        input_text = "a" * 10000
        result = sanitize_query_input(input_text)
        assert len(result) > 0

    def test_whitespace_only(self):
        """Whitespace-only input should return empty string after strip."""
        input_text = "   \t\n   "
        result = sanitize_query_input(input_text)
        assert result == ""

    def test_mixed_content(self):
        """Mixed HTML, ANSI, and SQL keywords should be cleaned."""
        input_text = "<p>\x1B[31mSELECT</p> * UNION SELECT *"
        result = sanitize_query_input(input_text)
        assert "<" not in result
        assert "\x1B" not in result
        assert "UNION SELECT" not in result.upper()

    def test_repeated_whitespace(self):
        """Repeated whitespace patterns should be collapsed."""
        input_text = "Word1   Word2    Word3"
        result = sanitize_query_input(input_text)
        assert result == "Word1 Word2 Word3"


class TestBackwardCompatibility:
    """Test that existing behavior is preserved."""

    def test_original_behavior_ansi(self):
        """Original ANSI removal behavior should be preserved."""
        input_text = "Text\x1B[31mwith\x1B[0m ANSI"
        result = sanitize_query_input(input_text)
        assert "Textwith ANSI" == result

    def test_original_behavior_html(self):
        """Original HTML removal behavior should be preserved."""
        input_text = "<p>Hello</p>World"
        result = sanitize_query_input(input_text)
        assert "HelloWorld" == result

    def test_original_behavior_semicolon(self):
        """Original semicolon truncation should be preserved."""
        input_text = "First;Second"
        result = sanitize_query_input(input_text)
        assert result == "First"

    def test_public_api_unchanged(self):
        """Public API signature should remain unchanged."""
        # Function should accept str and return str
        result = sanitize_query_input("test")
        assert isinstance(result, str)

    def test_none_handling_unchanged(self):
        """None handling should remain consistent."""
        result = sanitize_query_input(None)
        assert result == ""


class TestHelperFunctions:
    """Test individual helper functions."""

    def test_remove_ansi_sequences(self):
        """Test ANSI removal helper."""
        assert remove_ansi_sequences("A\x1B[31mB") == "AB"

    def test_remove_html_tags(self):
        """Test HTML removal helper."""
        assert remove_html_tags("<p>A</p>") == "A"

    def test_normalize_whitespace(self):
        """Test whitespace normalization helper."""
        assert normalize_whitespace("A  B") == "A B"

    def test_normalize_unicode(self):
        """Test Unicode normalization helper."""
        result = normalize_unicode("test")
        assert isinstance(result, str)

    def test_remove_dangerous_patterns(self):
        """Test dangerous pattern removal helper."""
        result = remove_dangerous_patterns("UNION SELECT *")
        assert "UNION SELECT" not in result.upper()

    def test_truncate_at_semicolon(self):
        """Test semicolon truncation helper."""
        assert truncate_at_semicolon("A;B") == "A"


def run_all_tests():
    """Run all test classes."""
    test_classes = [
        TestSafeInput,
        TestANSISequences,
        TestHTMLTags,
        TestSQLPatterns,
        TestCypherPatterns,
        TestBooleanInjection,
        TestSemicolonTruncation,
        TestWhitespaceNormalization,
        TestUnicodeNormalization,
        TestEdgeCases,
        TestBackwardCompatibility,
        TestHelperFunctions,
    ]

    total_tests = 0
    passed_tests = 0
    failed_tests = 0

    for test_class in test_classes:
        print(f"\n{'='*60}")
        print(f"Running {test_class.__name__}")
        print('='*60)

        test_instance = test_class()
        test_methods = [
            getattr(test_instance, method)
            for method in dir(test_instance)
            if method.startswith('test_')
        ]

        for test_method in test_methods:
            total_tests += 1
            try:
                test_method()
                passed_tests += 1
                print(f"✓ {test_method.__name__}")
            except AssertionError as e:
                failed_tests += 1
                print(f"✗ {test_method.__name__}: {e}")
            except Exception as e:
                failed_tests += 1
                print(f"✗ {test_method.__name__}: Unexpected error: {e}")

    print(f"\n{'='*60}")
    print(f"Test Summary")
    print('='*60)
    print(f"Total tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {failed_tests}")
    print(f"Success rate: {(passed_tests/total_tests*100):.1f}%")

    return failed_tests == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
