"""Money and currency handling built exclusively on :class:`decimal.Decimal`.

Floats are never used for monetary values. Amounts are stored as integer
minor units (cents) or ``Decimal`` in major units and only quantized with
explicit rounding contexts. ``divide`` deliberately lets ``Decimal`` raise
``DivisionByZero`` rather than returning ``None`` so callers must handle it.
"""

import re
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

_CENT = Decimal("0.01")
_TWO_PLACES = Decimal("1.00")
_CURRENCY_CODE_RE = re.compile(r"^[A-Z]{3}$")


def to_minor(amount):
    """Convert ``Decimal`` (or str/int) amount to integer minor units.

    ``Decimal("12.34")`` -> ``1234``. Raises ``ValueError`` when the input
    has more than two decimal places or is not a valid amount.
    """
    try:
        value = Decimal(amount)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"cannot convert {amount!r} to Decimal") from exc
    if value != value.to_integral():
        exponent = -value.as_tuple().exponent
        if exponent > 2:
            raise ValueError(
                f"amount {amount!r} has more than 2 decimal places"
            )
    return int((value * 100).to_integral_value(rounding=ROUND_HALF_UP))


def from_minor(minor):
    """Convert integer minor units (cents) to a ``Decimal`` major amount."""
    return (Decimal(int(minor)) / 100).quantize(_TWO_PLACES)


def format_money(amount, *, currency="USD", thousands_sep=True):
    """Format a ``Decimal`` amount as ``"1,234.56 USD"``."""
    value = Decimal(amount).quantize(_TWO_PLACES, rounding=ROUND_HALF_UP)
    sign, digits, _ = value.as_tuple()
    digits = "".join(map(str, digits)).zfill(2)
    integer, fraction = digits[:-2], digits[-2:]
    integer = int(integer or "0")
    if thousands_sep:
        integer = f"{integer:,}"
    return f"{'-' if sign else ''}{integer}.{fraction} {currency}"


def add(a, b):
    """Add two ``Decimal`` amounts and quantize to 2 decimal places."""
    return (Decimal(a) + Decimal(b)).quantize(_TWO_PLACES)


def subtract(a, b):
    """Subtract ``b`` from ``a`` and quantize to 2 decimal places."""
    return (Decimal(a) - Decimal(b)).quantize(_TWO_PLACES)


def multiply(a, b):
    """Multiply two ``Decimal`` values and quantize to 2 decimal places."""
    return (Decimal(a) * Decimal(b)).quantize(_TWO_PLACES)


def divide(a, b):
    """Divide ``a`` by ``b`` and quantize to 2 decimal places.

    Raises ``decimal.DivisionByZero`` when ``b`` is zero.
    """
    return (Decimal(a) / Decimal(b)).quantize(_TWO_PLACES)


def is_valid_currency_code(code):
    """Return ``True`` if ``code`` is exactly three uppercase letters."""
    return isinstance(code, str) and bool(_CURRENCY_CODE_RE.fullmatch(code))


def convert_minor(amount_minor, rate):
    """Convert minor units by a ``Decimal`` rate, rounding half-up per cent.

    ``rate`` must be a ``Decimal``; anything else raises ``TypeError``.
    """
    if not isinstance(rate, Decimal):
        raise TypeError(f"rate must be Decimal, got {type(rate).__name__}")
    converted = Decimal(int(amount_minor)) * rate
    return int(converted.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
