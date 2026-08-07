"""Tests for :mod:`src.utils.money`."""

from decimal import Decimal, DivisionByZero

import pytest

from src.utils.money import (
    add,
    convert_minor,
    divide,
    format_money,
    from_minor,
    is_valid_currency_code,
    multiply,
    subtract,
    to_minor,
)


class TestToMinor:
    def test_whole_dollars(self):
        assert to_minor(Decimal("12")) == 1200

    def test_with_cents(self):
        assert to_minor(Decimal("12.34")) == 1234

    def test_string_input(self):
        assert to_minor("12.34") == 1234

    def test_int_input(self):
        assert to_minor(7) == 700

    def test_single_decimal_place(self):
        assert to_minor(Decimal("0.5")) == 50

    def test_negative_amount(self):
        assert to_minor(Decimal("-3.20")) == -320

    def test_zero(self):
        assert to_minor(Decimal("0")) == 0

    def test_three_decimal_places_raises(self):
        with pytest.raises(ValueError):
            to_minor(Decimal("1.234"))

    def test_non_numeric_raises(self):
        with pytest.raises(ValueError):
            to_minor("abc")

    def test_none_raises(self):
        with pytest.raises((TypeError, ValueError)):
            to_minor(None)


class TestFromMinor:
    def test_round_trip(self):
        assert from_minor(1234) == Decimal("12.34")

    def test_zero(self):
        assert from_minor(0) == Decimal("0.00")

    def test_large_amount(self):
        assert from_minor(1_000_000) == Decimal("10000.00")

    def test_negative(self):
        assert from_minor(-25) == Decimal("-0.25")

    def test_to_minor_round_trip(self):
        original = Decimal("123.45")
        assert from_minor(to_minor(original)) == original


class TestFormatMoney:
    def test_grouping_default(self):
        assert format_money(Decimal("1234.56")) == "1,234.56 USD"

    def test_no_grouping(self):
        assert (
            format_money(Decimal("1234.56"), thousands_sep=False)
            == "1234.56 USD"
        )

    def test_currency_suffix(self):
        assert (
            format_money(Decimal("99.99"), currency="EUR") == "99.99 EUR"
        )

    def test_negative_amount(self):
        assert format_money(Decimal("-5.5")) == "-5.50 USD"

    def test_integer_input(self):
        assert format_money(1234) == "1,234.00 USD"

    def test_large_value(self):
        assert (
            format_money(Decimal("1234567890.1"))
            == "1,234,567,890.10 USD"
        )

    def test_string_input(self):
        assert format_money("12.30") == "12.30 USD"


class TestArithmetic:
    def test_add_no_float_drift(self):
        assert add(Decimal("0.1"), Decimal("0.2")) == Decimal("0.30")

    def test_add_quantization(self):
        assert add(Decimal("1.005"), Decimal("0")) == Decimal("1.00")

    def test_subtract_exact(self):
        assert subtract(Decimal("0.3"), Decimal("0.1")) == Decimal("0.20")

    def test_subtract_negative_result(self):
        assert subtract(Decimal("0.05"), Decimal("0.10")) == Decimal("-0.05")

    def test_multiply_quantization(self):
        assert multiply(Decimal("2.50"), Decimal("3")) == Decimal("7.50")

    def test_multiply_rounds_half_up(self):
        assert multiply(Decimal("0.05"), Decimal("0.05")) == Decimal("0.00")

    def test_divide_quantization(self):
        assert divide(Decimal("10"), Decimal("3")) == Decimal("3.33")

    def test_divide_exact(self):
        assert divide(Decimal("1"), Decimal("4")) == Decimal("0.25")

    def test_divide_by_zero_raises(self):
        with pytest.raises(DivisionByZero):
            divide(Decimal("1"), Decimal("0"))

    def test_operations_accept_strings(self):
        assert add("0.1", "0.2") == Decimal("0.30")
        assert multiply("1.5", "2") == Decimal("3.00")


class TestIsValidCurrencyCode:
    def test_valid(self):
        assert is_valid_currency_code("USD")
        assert is_valid_currency_code("EUR")
        assert is_valid_currency_code("JPY")

    def test_invalid_length(self):
        assert not is_valid_currency_code("US")
        assert not is_valid_currency_code("USDT")

    def test_lowercase_rejected(self):
        assert not is_valid_currency_code("usd")

    def test_digits_rejected(self):
        assert not is_valid_currency_code("U1D")

    def test_empty_rejected(self):
        assert not is_valid_currency_code("")

    def test_non_string_rejected(self):
        assert not is_valid_currency_code(None)
        assert not is_valid_currency_code(123)


class TestConvertMinor:
    def test_basic_rate(self):
        assert convert_minor(100, Decimal("1.5")) == 150

    def test_rate_below_one(self):
        assert convert_minor(200, Decimal("0.5")) == 100

    def test_rounding_half_up(self):
        assert convert_minor(100, Decimal("0.005")) == 1

    def test_rounding_down(self):
        assert convert_minor(1, Decimal("0.004")) == 0

    def test_zero_minor(self):
        assert convert_minor(0, Decimal("2")) == 0

    def test_large_conversion(self):
        assert convert_minor(12_345, Decimal("1.07")) == 13_209

    def test_rate_must_be_decimal(self):
        with pytest.raises(TypeError):
            convert_minor(100, 1.5)
        with pytest.raises(TypeError):
            convert_minor(100, "1.5")

    def test_round_trip(self):
        assert convert_minor(to_minor("10.50"), Decimal("1")) == 1050
