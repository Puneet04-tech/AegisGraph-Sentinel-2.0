"""
Input Sanitizer for AegisGraph Sentinel

IMPORTANT SECURITY NOTICE:
This module provides input normalization and cleaning utilities only.
It is NOT a complete defense against SQL or Cypher injection attacks.

All database access MUST use parameterized queries/prepared statements.
This sanitizer is intended for:
- Removing ANSI escape sequences from terminal output
- Stripping HTML/XML tags from user input
- Normalizing whitespace
- Basic pattern cleanup for input hygiene

This is a defense-in-depth measure, not a primary security control.
"""

import re
import unicodedata
from typing import Optional


# ============================================================================
# COMPILED REGEX PATTERNS
# ============================================================================

# ANSI escape sequences - terminal control codes that can be used for
# log injection or terminal manipulation attacks
ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# HTML/XML tags - can be used for XSS or structure injection
HTML_TAG_PATTERN = re.compile(r"<[^>]*>")

# SQL injection patterns - these are common SQL injection techniques
# NOTE: Regex cannot prevent SQL injection. Use parameterized queries.
SQL_KEYWORD_PATTERNS = [
    # UNION-based injection - combines results from multiple queries
    re.compile(r"(?i)\bUNION\b\s+\bSELECT\b.*", re.DOTALL),
    # DROP statements - destructive database operations
    re.compile(r"(?i)\bDROP\b\s+\bDATABASE\b.*", re.DOTALL),
    re.compile(r"(?i)\bDROP\b\s+\bTABLE\b.*", re.DOTALL),
]

# Cypher injection patterns - Neo4j graph database query patterns
# NOTE: Regex cannot prevent Cypher injection. Use parameterized queries.
CYPHER_KEYWORD_PATTERNS = [
    # DELETE operations in MATCH queries
    re.compile(r"(?i)\bMATCH\b.*\bDELETE\b.*", re.DOTALL),
    # DETACH DELETE operations
    re.compile(r"(?i)\bMATCH\b.*\bDETACH\b.*", re.DOTALL),
]

# Boolean-based injection patterns - used to bypass authentication
BOOLEAN_INJECTION_PATTERNS = [
    # Classic OR 1=1 pattern and variants
    re.compile(r"(?i)\bOR\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?.*", re.DOTALL),
]

# All dangerous patterns combined for iteration
ALL_DANGEROUS_PATTERNS = [
    *SQL_KEYWORD_PATTERNS,
    *CYPHER_KEYWORD_PATTERNS,
    *BOOLEAN_INJECTION_PATTERNS,
]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def remove_ansi_sequences(text: str) -> str:
    """
    Remove ANSI escape sequences from input text.

    ANSI escape sequences are terminal control codes that can be used
    for log injection or terminal output manipulation.

    Args:
        text: Input string potentially containing ANSI codes

    Returns:
        String with ANSI sequences removed

    Examples:
        >>> remove_ansi_sequences("Hello\x1B[31mWorld")
        'HelloWorld'
    """
    return ANSI_ESCAPE_PATTERN.sub("", text)


def remove_html_tags(text: str) -> str:
    """
    Remove HTML/XML tags from input text.

    This is a basic tag stripper for input normalization. It does NOT
    prevent XSS attacks - proper output encoding is required for that.

    Args:
        text: Input string potentially containing HTML/XML tags

    Returns:
        String with tags removed

    Examples:
        >>> remove_html_tags("<p>Hello</p>World")
        'HelloWorld'
    """
    return HTML_TAG_PATTERN.sub("", text)


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in input text.

    Collapses multiple whitespace characters into single spaces and
    normalizes newlines. Preserves readability while cleaning up
    irregular spacing.

    Args:
        text: Input string with irregular whitespace

    Returns:
        String with normalized whitespace

    Examples:
        >>> normalize_whitespace("Hello   World")
        'Hello World'
    """
    # Replace various whitespace characters with space
    text = re.sub(r"[\r\n\t\f\v]+", " ", text)
    # Collapse multiple spaces into single space
    text = re.sub(r" +", " ", text)
    return text


def normalize_unicode(text: str) -> str:
    """
    Normalize Unicode characters to NFC form.

    Unicode normalization prevents character encoding issues and
    canonicalization attacks where different byte representations
    of the same character could bypass filters.

    Args:
        text: Input string with potential Unicode variations

    Returns:
        String in NFC normalized形式

    Examples:
        >>> normalize_unicode("café")
        'café'  # NFC normalized
    """
    return unicodedata.normalize("NFC", text)


def remove_dangerous_patterns(text: str) -> str:
    """
    Remove known dangerous SQL/Cypher injection patterns.

    IMPORTANT: This is NOT a security control against injection attacks.
    It only provides basic input hygiene. All database queries MUST
    use parameterized queries/prepared statements.

    This function removes patterns that are commonly used in injection
    attacks, but attackers can always bypass regex-based filters.

    Args:
        text: Input string potentially containing dangerous patterns

    Returns:
        String with matched patterns removed
    """
    cleaned = text
    for pattern in ALL_DANGEROUS_PATTERNS:
        cleaned = pattern.sub("", cleaned)
    return cleaned


def truncate_at_semicolon(text: str) -> str:
    """
    Truncate input at the first semicolon to prevent stacked queries.

    Many injection attacks attempt to stack multiple queries using
    semicolons. This prevents the trailing portion from being processed.

    Args:
        text: Input string potentially containing stacked queries

    Returns:
        String truncated at first semicolon, or original if none found

    Examples:
        >>> truncate_at_semicolon("SELECT *; DROP TABLE")
        'SELECT *'
    """
    return text.split(";")[0]


# ============================================================================
# MAIN SANITIZATION FUNCTION
# ============================================================================

def sanitize_query_input(user_input: Optional[str]) -> str:
    """
    Sanitize user input for query processing.

    SECURITY WARNING: This function is NOT an injection prevention mechanism.
    It provides input normalization and basic hygiene only.

    All database access MUST use parameterized queries. This function:
    - Does not replace proper security controls
    - Cannot prevent all injection attacks
    - Should be used as defense-in-depth, not primary security

    The function performs the following normalizations:
    1. Unicode normalization (NFC form)
    2. ANSI escape sequence removal
    3. HTML/XML tag removal
    4. Semicolon truncation (prevents stacked queries)
    5. Dangerous pattern removal
    6. Whitespace normalization

    Args:
        user_input: Raw user input string, or None/empty string

    Returns:
        Sanitized string safe for further processing. Returns empty string
        for None or empty input.

    Examples:
        >>> sanitize_query_input("Hello World")
        'Hello World'
        >>> sanitize_query_input(None)
        ''
        >>> sanitize_query_input("<script>alert(1)</script>")
        'alert(1)'
    """
    if not user_input:
        return ""

    # Step 1: Unicode normalization
    cleaned = normalize_unicode(user_input)

    # Step 2: Remove ANSI escape sequences
    cleaned = remove_ansi_sequences(cleaned)

    # Step 3: Remove HTML/XML tags
    cleaned = remove_html_tags(cleaned)

    # Step 4: Truncate at semicolon to prevent stacked queries
    cleaned = truncate_at_semicolon(cleaned)

    # Step 5: Remove dangerous patterns (defense-in-depth only)
    cleaned = remove_dangerous_patterns(cleaned)

    # Step 6: Normalize whitespace
    cleaned = normalize_whitespace(cleaned)

    return cleaned.strip()
