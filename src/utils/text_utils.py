"""Text processing utilities.

Dependency-free helpers for slugifying identifiers, truncating and masking
strings, normalizing whitespace, parsing simple CSV lines, converting
identifier casing, and scrubbing log messages before they are emitted.
"""

import re
import unicodedata

_ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def slugify(value):
    """Convert ``value`` into a URL-safe slug.

    The text is lowercased, diacritics are stripped, runs of non-alphanumeric
    characters become single hyphens, and leading/trailing hyphens are removed.
    """
    if value is None:
        return ""
    value = unicodedata.normalize("NFKD", str(value))
    value = "".join(c for c in value if not unicodedata.combining(c))
    value = re.sub(r"[^a-z0-9]+", "-", value.lower())
    return value.strip("-")


def truncate(value, max_length, suffix="..."):
    """Truncate ``value`` to ``max_length`` including ``suffix``.

    Strings already at or below the limit are returned unchanged. When the
    limit cannot hold the suffix, the suffix itself is cut to fit.
    """
    if value is None:
        return ""
    value = str(value)
    if max_length <= 0:
        return ""
    if len(value) <= max_length:
        return value
    if max_length <= len(suffix):
        return suffix[:max_length]
    return value[: max_length - len(suffix)] + suffix


def mask(text, visible=4, mask_char="*"):
    """Mask the middle of ``text``, keeping the first and last ``visible``.

    Strings with no middle section (``len <= 2 * visible``) are unchanged.
    """
    if text is None:
        return ""
    text = str(text)
    visible = max(visible, 0)
    if visible == 0:
        return mask_char * len(text)
    if len(text) <= visible * 2:
        return text
    middle = len(text) - visible * 2
    return text[:visible] + mask_char * middle + text[-visible:]


def normalize_whitespace(value):
    """Collapse all whitespace runs to single spaces and strip the result."""
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def split_csv_line(line):
    """Parse a single CSV line into a list of fields.

    Quoted fields may contain embedded commas and doubled double quotes
    (``""``) which decode to a single quote. No third-party CSV dependency
    is used.
    """
    if line is None:
        return []
    line = str(line)
    if line == "":
        return [""]
    fields = []
    current = []
    in_quotes = False
    i = 0
    n = len(line)
    while i < n:
        char = line[i]
        if in_quotes:
            if char == '"':
                if i + 1 < n and line[i + 1] == '"':
                    current.append('"')
                    i += 2
                    continue
                in_quotes = False
            else:
                current.append(char)
        else:
            if char == '"':
                in_quotes = True
            elif char == ",":
                fields.append("".join(current))
                current = []
            else:
                current.append(char)
        i += 1
    fields.append("".join(current))
    return fields


def camel_to_snake(value):
    """Convert camelCase or PascalCase identifiers to snake_case."""
    if value is None:
        return ""
    value = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", str(value))
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return value.lower()


def sanitize_log_message(value):
    """Strip ANSI escape sequences and control characters for safe logging."""
    if value is None:
        return ""
    value = _ANSI_OSC_RE.sub("", str(value))
    value = _ANSI_CSI_RE.sub("", value)
    return _CONTROL_RE.sub("", value)
