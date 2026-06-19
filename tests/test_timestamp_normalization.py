import pytest
from datetime import datetime, timezone
from src.features.velocity_calculator import VelocityCalculator


@pytest.fixture
def calc():
    return VelocityCalculator()


# --- None input ---
def test_none_returns_fallback(calc):
    assert calc._normalize_timestamp(None, 99.0) == 99.0


# --- Unix timestamps in seconds ---
def test_unix_timestamp_seconds_integer(calc):
    assert calc._normalize_timestamp(1700000000, 0.0) == 1700000000.0


def test_unix_timestamp_seconds_float(calc):
    assert calc._normalize_timestamp(1700000000.5, 0.0) == 1700000000.5


def test_unix_timestamp_zero(calc):
    assert calc._normalize_timestamp(0, 99.0) == 0.0


def test_unix_timestamp_negative(calc):
    assert calc._normalize_timestamp(-100.0, 0.0) == -100.0


# --- Unix timestamps in milliseconds ---
def test_unix_timestamp_milliseconds_integer(calc):
    result = calc._normalize_timestamp(1700000000000, 0.0)
    assert result == 1700000000000.0


def test_unix_timestamp_milliseconds_float(calc):
    result = calc._normalize_timestamp(1700000000000.5, 0.0)
    assert result == 1700000000000.5


# --- ISO 8601 timestamp strings ---
def test_iso_string_with_z(calc):
    result = calc._normalize_timestamp("2024-01-01T12:00:00Z", 0.0)
    assert isinstance(result, float)
    assert result > 0.0


def test_iso_string_with_utc_offset(calc):
    result = calc._normalize_timestamp("2024-01-01T12:00:00+05:30", 0.0)
    assert isinstance(result, float)
    assert result > 0.0


def test_iso_string_without_timezone(calc):
    result = calc._normalize_timestamp("2024-01-01T12:00:00", 0.0)
    assert isinstance(result, float)
    assert result > 0.0


def test_iso_string_date_only(calc):
    result = calc._normalize_timestamp("2024-01-01", 0.0)
    assert isinstance(result, float)
    assert result > 0.0


# --- datetime objects ---
def test_datetime_with_timezone(calc):
    dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    result = calc._normalize_timestamp(dt, 0.0)
    assert result == dt.timestamp()


def test_datetime_without_timezone(calc):
    dt = datetime(2024, 1, 1, 12, 0, 0)
    result = calc._normalize_timestamp(dt, 0.0)
    assert isinstance(result, float)
    assert result > 0.0


# --- Malformed and unsupported formats ---
def test_malformed_string_returns_fallback(calc):
    assert calc._normalize_timestamp("not-a-date", 42.0) == 42.0


def test_empty_string_returns_fallback(calc):
    assert calc._normalize_timestamp("", 42.0) == 42.0


def test_unsupported_type_list_returns_fallback(calc):
    assert calc._normalize_timestamp(["2024", "01", "01"], 99.0) == 99.0


def test_unsupported_type_dict_returns_fallback(calc):
    assert calc._normalize_timestamp({"timestamp": 1000}, 55.0) == 55.0


def test_random_string_returns_fallback(calc):
    assert calc._normalize_timestamp("abc-xyz-123", 77.0) == 77.0 

# --- Unix timestamp as string ---
def test_unix_timestamp_string(calc):
    result = calc._normalize_timestamp("1700000000", 0.0)
    assert result == 1700000000.0


# --- RFC 3339 with space instead of T ---
def test_rfc3339_space_separator(calc):
    result = calc._normalize_timestamp("2024-01-01 12:00:00+00:00", 0.0)
    assert isinstance(result, float)
    assert result > 0.0


# --- Common date formats ---
def test_dot_separated_date(calc):
    result = calc._normalize_timestamp("2024.01.01", 0.0)
    assert isinstance(result, float)
    assert result > 0.0


def test_slash_separated_date_dmy(calc):
    result = calc._normalize_timestamp("01/01/2024", 0.0)
    assert isinstance(result, float)
    assert result > 0.0


def test_slash_separated_date_mdy(calc):
    result = calc._normalize_timestamp("01/15/2024", 0.0)
    assert isinstance(result, float)
    assert result > 0.0


def test_dash_separated_date_dmy(calc):
    result = calc._normalize_timestamp("01-01-2024", 0.0)
    assert isinstance(result, float)
    assert result > 0.0


def test_month_name_short(calc):
    result = calc._normalize_timestamp("Jan 01 2024", 0.0)
    assert isinstance(result, float)
    assert result > 0.0


def test_month_name_full(calc):
    result = calc._normalize_timestamp("January 01 2024", 0.0)
    assert isinstance(result, float)
    assert result > 0.0 
