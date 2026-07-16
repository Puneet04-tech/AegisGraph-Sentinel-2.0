import json
from app import (
    _accessible_status,
    _escape_network_tooltip_value,
    _json_for_inline_script,
)


def test_accessible_status():
    assert _accessible_status("✅", "API Online") == "✅ API Online (API Online)"


def test_escape_html_tags():
    assert (
        _escape_network_tooltip_value("<script>")
        == "&lt;script&gt;"
    )


def test_escape_quotes():
    assert (
        _escape_network_tooltip_value('"hello"')
        == "&quot;hello&quot;"
    )


def test_escape_none():
    assert _escape_network_tooltip_value(None) == "None"


def test_json_unicode():
    value = {"name": "こんにちは"}
    result = _json_for_inline_script(value)
    assert json.loads(result) == value


def test_json_special_characters():
    value = {"text": "<>&"}
    result = _json_for_inline_script(value)
    assert json.loads(result) == value


def test_json_none():
    assert _json_for_inline_script(None) == "null"