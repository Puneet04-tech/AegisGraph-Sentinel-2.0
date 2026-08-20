import json
from datetime import date, datetime
from decimal import Decimal
from uuid import UUID

import pytest

from src.utils.json_utils import (
    deep_merge,
    json_dumps,
    json_loads,
    safe_json_dumps,
    to_camel_case,
    to_snake_case,
)


class Unserializable:
    def __repr__(self):
        raise RuntimeError("repr failed")


class StrFallback:
    def __str__(self):
        return "fallback-repr"


@pytest.mark.parametrize(
    ("obj", "expected"),
    [
        (datetime(2024, 1, 2, 3, 4, 5), '"2024-01-02T03:04:05"'),
        (date(2024, 1, 2), '"2024-01-02"'),
        (UUID("12345678-1234-5678-1234-567812345678"), '"12345678-1234-5678-1234-567812345678"'),
        (Decimal("3.14"), "3.14"),
        ({"a": 1, "b": "x"}, '{"a": 1, "b": "x"}'),
        ([1, 2, 3], "[1, 2, 3]"),
        ("hello", '"hello"'),
        (None, "null"),
        (True, "true"),
        (42, "42"),
    ],
)
def test_json_dumps_plain_and_special(obj, expected):
    assert json_dumps(obj) == expected


def test_json_dumps_nested_mixed_types():
    obj = {
        "when": datetime(2024, 5, 6, 7, 8, 9),
        "day": date(2024, 5, 6),
        "id": UUID("00000000-0000-0000-0000-000000000001"),
        "amount": Decimal("9.99"),
        "items": [{"flag": True}, None],
    }
    parsed = json.loads(json_dumps(obj))
    assert parsed["when"] == "2024-05-06T07:08:09"
    assert parsed["day"] == "2024-05-06"
    assert parsed["id"] == "00000000-0000-0000-0000-000000000001"
    assert parsed["amount"] == 9.99
    assert parsed["items"] == [{"flag": True}, None]


def test_json_dumps_sort_keys():
    out = json_dumps({"b": 1, "a": 2}, sort_keys=True)
    assert out == '{"a": 2, "b": 1}'


def test_json_dumps_unknown_object_falls_back_to_str():
    assert json_dumps(StrFallback()) == '"fallback-repr"'


def test_json_dumps_custom_kwargs_passthrough():
    out = json_dumps({"x": Decimal("1.5")}, indent=2)
    assert json.loads(out) == {"x": 1.5}


def test_json_dumps_numpy_scalars():
    np = pytest.importorskip("numpy")
    assert json_dumps(np.int64(5)) == "5"
    assert json_dumps(np.float64(2.5)) == "2.5"
    assert json_dumps(np.array([1, 2])) == "[1, 2]"
    assert json_dumps(np.float32(1.25)) == "1.25"


def test_json_loads_valid():
    assert json_loads('{"a": [1, 2]}') == {"a": [1, 2]}
    assert json_loads("42") == 42


@pytest.mark.parametrize(
    "text",
    [
        "{not json",
        '{"a": }',
        "",
        "[1, 2",
        "null extra",
    ],
)
def test_json_loads_invalid_raises(text):
    with pytest.raises(json.JSONDecodeError):
        json_loads(text)


def test_safe_json_dumps_serializable():
    assert safe_json_dumps({"ok": True}) == '{"ok": true}'


def test_safe_json_dumps_unserializable_returns_default():
    assert safe_json_dumps(Unserializable()) == "null"


def test_safe_json_dumps_custom_default_str():
    assert safe_json_dumps(Unserializable(), default_str="{}") == "{}"


def test_safe_json_dumps_default_never_raises():
    assert safe_json_dumps(Unserializable()) == "null"
    circular: dict = {}
    circular["self"] = circular
    assert safe_json_dumps(circular) == "null"


def test_deep_merge_nested():
    base = {"a": {"x": 1, "y": 2}, "b": 3}
    override = {"a": {"y": 9, "z": 4}}
    assert deep_merge(base, override) == {"a": {"x": 1, "y": 9, "z": 4}, "b": 3}


def test_deep_merge_override_wins_on_scalar():
    base = {"a": 1}
    override = {"a": 2}
    assert deep_merge(base, override) == {"a": 2}


def test_deep_merge_non_dict_value_replaces_dict():
    base = {"a": {"x": 1}}
    override = {"a": "flat"}
    assert deep_merge(base, override) == {"a": "flat"}


def test_deep_merge_does_not_mutate_inputs():
    base = {"a": {"x": 1}}
    override = {"a": {"y": 2}}
    deep_merge(base, override)
    assert base == {"a": {"x": 1}}
    assert override == {"a": {"y": 2}}


def test_deep_merge_empty_dicts():
    assert deep_merge({}, {}) == {}
    assert deep_merge({"a": 1}, {}) == {"a": 1}
    assert deep_merge({}, {"a": 1}) == {"a": 1}


@pytest.mark.parametrize(
    ("snake", "expected"),
    [
        ("user_name", "userName"),
        ("already_camel", "alreadyCamel"),
        ("first_name_last_name", "firstNameLastName"),
        ("plain", "plain"),
        ("", ""),
        ("a", "a"),
        ("a_b", "aB"),
        ("snake_case", "snakeCase"),
    ],
)
def test_to_camel_case(snake, expected):
    assert to_camel_case(snake) == expected


@pytest.mark.parametrize(
    ("camel", "expected"),
    [
        ("userName", "user_name"),
        ("HTTPServer", "http_server"),
        ("already_snake", "already_snake"),
        ("a", "a"),
        ("", ""),
        ("userID", "user_id"),
        ("XMLHttpRequest", "xml_http_request"),
    ],
)
def test_to_snake_case(camel, expected):
    assert to_snake_case(camel) == expected
