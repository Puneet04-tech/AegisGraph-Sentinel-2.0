"""PII masking utilities.

Deterministic, dependency-free helpers for masking personally identifiable
information (email addresses, phone numbers, card numbers, SSNs) before
logging, auditing, or storing it.
"""

import copy
from typing import Any

_PII_KEYS = {"email", "phone", "card", "card_number", "ssn", "pan"}


def mask_email(email: str) -> str:
    """Mask the local part of an email, keeping the first character and domain.

    Invalid inputs (missing '@', empty parts, domain without a dot) are
    returned unchanged.
    """
    if not isinstance(email, str):
        return email
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if not local or not domain or "@" in domain or "." not in domain:
        return email
    return local[0] + "*" * (len(local) - 1) + "@" + domain


def _mask_digits(value: str, keep_last: int) -> str:
    """Replace every digit except the last ``keep_last`` with 'X'.

    Non-digit characters (separators, prefixes) are preserved so the output
    length and shape match the input.
    """
    digit_positions = [i for i, char in enumerate(value) if char.isdigit()]
    keep_from = max(len(digit_positions) - keep_last, 0)
    keep_positions = set(digit_positions[keep_from:])
    result = []
    for i, char in enumerate(value):
        if char.isdigit():
            result.append(char if i in keep_positions else "X")
        else:
            result.append(char)
    return "".join(result)


def _restore_country_code(original: str, masked: str) -> str:
    if not original.startswith("+"):
        return masked
    result = list(masked)
    for i, char in enumerate(original[1:], start=1):
        if not char.isdigit():
            break
        if i < len(result):
            result[i] = char
    return "".join(result)


def mask_phone(phone: str) -> str:
    """Mask a phone number, keeping the last four digits.

    A leading country code (digits following '+') is preserved, and any
    separators (e.g. '-', spaces) are retained so the output keeps its shape.
    """
    if not isinstance(phone, str):
        return phone
    return _restore_country_code(phone, _mask_digits(phone, keep_last=4))


def mask_card_number(card: str) -> str:
    """Mask a card number, keeping only the last four digits as 'X's.

    Separators (e.g. '-') are preserved when present.
    """
    if not isinstance(card, str):
        return card
    return _mask_digits(card, keep_last=4)


def mask_ssn(ssn: str) -> str:
    """Mask the first five digits of an SSN (XXX-XX-####)."""
    if not isinstance(ssn, str):
        return ssn
    return _mask_digits(ssn, keep_last=4)


def mask_generic(value: str, *, keep_first: int = 2, keep_last: int = 2) -> str:
    """Mask the middle characters of a string with '*'.

    Strings shorter than or equal to ``keep_first + keep_last`` characters
    are returned unchanged.
    """
    if not isinstance(value, str):
        return value
    if len(value) <= keep_first + keep_last:
        return value
    middle = len(value) - keep_first - keep_last
    return value[:keep_first] + "*" * middle + value[-keep_last:]


def _mask_value(key: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    k = key.lower()
    if k == "email":
        return mask_email(value)
    if k == "phone":
        return mask_phone(value)
    if k in ("card", "card_number", "pan"):
        return mask_card_number(value)
    if k == "ssn":
        return mask_ssn(value)
    return value


def _mask_in_place(node: Any) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                _mask_in_place(value)
            elif isinstance(key, str) and key.lower() in _PII_KEYS:
                node[key] = _mask_value(key, value)
    elif isinstance(node, list):
        for item in node:
            _mask_in_place(item)


def mask_payload(payload: dict) -> dict:
    """Return a deep copy of ``payload`` with PII values masked.

    Keys matching any of {'email', 'phone', 'card', 'card_number', 'ssn',
    'pan'} are masked in place within a copy; every other key is preserved.
    """
    result = copy.deepcopy(payload)
    _mask_in_place(result)
    return result
