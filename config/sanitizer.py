import re

# Regex to match ANSI escape codes
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Regex to match HTML/XML tags
HTML_TAGS = re.compile(r"<[^>]*>")

# SQL/Cypher dangerous patterns that consume the trailing query
DANGEROUS_PATTERNS = [
    r"(?i)\bUNION\b\s+\bSELECT\b.*",
    r"(?i)\bMATCH\b.*\bDELETE\b.*",
    r"(?i)\bMATCH\b.*\bDETACH\b.*",
    r"(?i)\bDROP\b\s+\bDATABASE\b.*",
    r"(?i)\bDROP\b\s+\bTABLE\b.*",
    r"(?i)\bOR\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?.*",
]


def sanitize_query_input(user_input: str) -> str:
    """Sanitizes user input queries to prevent injection attacks."""
    if not user_input:
        return ""

    # 1. Remove ANSI escape markers
    cleaned = ANSI_ESCAPE.sub("", user_input)

    # 2. Remove HTML tags
    cleaned = HTML_TAGS.sub("", cleaned)

    # 3. Split on semicolon to prevent stacked queries/commands
    cleaned = cleaned.split(";")[0]

    # 4. Clean malicious pattern occurrences by stripping trailing query
    for pattern in DANGEROUS_PATTERNS:
        cleaned = re.sub(pattern, "", cleaned)

    return cleaned.strip()
