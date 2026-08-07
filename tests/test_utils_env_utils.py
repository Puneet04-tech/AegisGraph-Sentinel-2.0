"""Unit tests for the environment variable helper utilities."""

import pytest

from src.utils.env_utils import (
    env_required,
    get_bool_env,
    get_env,
    get_float_env,
    get_int_env,
    get_list_env,
    mask_env_value,
)


class TestGetEnv:
    def test_returns_value_when_set(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "hello")
        assert get_env("TEST_VAR") == "hello"

    def test_returns_default_when_missing(self, monkeypatch):
        monkeypatch.delenv("TEST_VAR", raising=False)
        assert get_env("TEST_VAR", "fallback") == "fallback"

    def test_returns_default_when_empty(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "")
        assert get_env("TEST_VAR", "fallback") == "fallback"

    def test_returns_none_when_missing_and_no_default(self, monkeypatch):
        monkeypatch.delenv("TEST_VAR", raising=False)
        assert get_env("TEST_VAR") is None


class TestGetBoolEnv:
    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "True", "yes", "on"])
    def test_truthy_variants(self, monkeypatch, value):
        monkeypatch.setenv("TEST_VAR", value)
        assert get_bool_env("TEST_VAR") is True

    @pytest.mark.parametrize("value", ["0", "false", "FALSE", "no", "off"])
    def test_falsy_variants(self, monkeypatch, value):
        monkeypatch.setenv("TEST_VAR", value)
        assert get_bool_env("TEST_VAR") is False

    def test_invalid_value_uses_default(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "maybe")
        assert get_bool_env("TEST_VAR") is False
        assert get_bool_env("TEST_VAR", default=True) is True

    def test_missing_uses_default_true(self, monkeypatch):
        monkeypatch.delenv("TEST_VAR", raising=False)
        assert get_bool_env("TEST_VAR", default=True) is True


class TestGetIntEnv:
    def test_valid_integer(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "42")
        assert get_int_env("TEST_VAR") == 42

    def test_negative_integer(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "-7")
        assert get_int_env("TEST_VAR") == -7

    def test_invalid_uses_default(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "abc")
        assert get_int_env("TEST_VAR") == 0
        assert get_int_env("TEST_VAR", default=5) == 5

    def test_float_string_uses_default(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "3.14")
        assert get_int_env("TEST_VAR") == 0

    def test_missing_uses_default(self, monkeypatch):
        monkeypatch.delenv("TEST_VAR", raising=False)
        assert get_int_env("TEST_VAR", default=9) == 9


class TestGetFloatEnv:
    def test_valid_float(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "3.14")
        assert get_float_env("TEST_VAR") == pytest.approx(3.14)

    def test_integer_string_parses_as_float(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "2")
        assert get_float_env("TEST_VAR") == pytest.approx(2.0)

    def test_invalid_uses_default(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "not-a-number")
        assert get_float_env("TEST_VAR") == 0.0
        assert get_float_env("TEST_VAR", default=1.5) == pytest.approx(1.5)

    def test_missing_uses_default(self, monkeypatch):
        monkeypatch.delenv("TEST_VAR", raising=False)
        assert get_float_env("TEST_VAR", default=2.5) == pytest.approx(2.5)


class TestGetListEnv:
    def test_splits_on_comma(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "a,b,c")
        assert get_list_env("TEST_VAR") == ["a", "b", "c"]

    def test_strips_whitespace(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", " a , b , c ")
        assert get_list_env("TEST_VAR") == ["a", "b", "c"]

    def test_filters_empty_entries(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "a,,b,")
        assert get_list_env("TEST_VAR") == ["a", "b"]

    def test_missing_returns_default(self, monkeypatch):
        monkeypatch.delenv("TEST_VAR", raising=False)
        assert get_list_env("TEST_VAR", default=["x"]) == ["x"]

    def test_missing_returns_empty_list(self, monkeypatch):
        monkeypatch.delenv("TEST_VAR", raising=False)
        assert get_list_env("TEST_VAR") == []

    def test_custom_separator(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "a;b;c")
        assert get_list_env("TEST_VAR", sep=";") == ["a", "b", "c"]


class TestEnvRequired:
    def test_returns_value_when_set(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "needed")
        assert env_required("TEST_VAR") == "needed"

    def test_raises_when_missing(self, monkeypatch):
        monkeypatch.delenv("TEST_VAR", raising=False)
        with pytest.raises(RuntimeError, match="Missing required env var: TEST_VAR"):
            env_required("TEST_VAR")

    def test_raises_when_empty(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR", "")
        with pytest.raises(RuntimeError, match="Missing required env var: TEST_VAR"):
            env_required("TEST_VAR")


class TestMaskEnvValue:
    def test_set_value_is_redacted(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "super-secret-value")
        assert mask_env_value("API_KEY") == "API_KEY=<redacted>"

    def test_unset_value_is_marked(self, monkeypatch):
        monkeypatch.delenv("API_KEY", raising=False)
        assert mask_env_value("API_KEY") == "API_KEY=<unset>"

    def test_never_contains_actual_value(self, monkeypatch):
        secret = "hunter2-secret"
        monkeypatch.setenv("API_KEY", secret)
        result = mask_env_value("API_KEY")
        assert secret not in result
