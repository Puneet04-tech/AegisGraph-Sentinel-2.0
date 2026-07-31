"""Unit tests for src.security.secret_scanner.scan_for_secrets."""

from src.security.secret_scanner import scan_for_secrets


def test_flat_dict_sensitive_keys() -> None:
    result = scan_for_secrets({"api_key": "abc", "name": "x", "token": "y"})
    assert result["detected_keys"] == ["api_key", "token"]
    assert result["count"] == 2


def test_no_sensitive_keys() -> None:
    result = scan_for_secrets({"name": "x", "age": 30, "city": "nyc"})
    assert result["detected_keys"] == []
    assert result["count"] == 0


def test_nested_dict_recursion() -> None:
    data = {"user": {"password": "p", "profile": {"api_key": "k"}}}
    result = scan_for_secrets(data)
    assert set(result["detected_keys"]) == {"password", "api_key"}
    assert result["count"] == 2


def test_list_of_dicts_recursion() -> None:
    data = [{"access_token": "a"}, {"name": "x"}, {"secret": "s"}]
    result = scan_for_secrets(data)
    assert set(result["detected_keys"]) == {"access_token", "secret"}
    assert result["count"] == 2


def test_tuple_of_dicts_recursion() -> None:
    data = ({"private_key": "k"}, [{"name": "x"}])
    result = scan_for_secrets(data)
    assert result["detected_keys"] == ["private_key"]
    assert result["count"] == 1


def test_duplicate_keys_counted_once_per_occurrence() -> None:
    data = {"token": "a", "nested": {"token": "b"}}
    result = scan_for_secrets(data)
    assert result["detected_keys"] == ["token", "token"]
    assert result["count"] == 2


def test_case_and_separator_normalization() -> None:
    data = {
        "API-Key": "a",
        "api key": "b",
        "Bearer_Token": "c",
        "ACCESS TOKEN": "d",
        "Connection-String": "e",
    }
    result = scan_for_secrets(data)
    assert result["count"] == 5


def test_substring_tokens_do_not_match() -> None:
    # "tokenized", "secrecy" contain the token as a substring but are not
    # underscore-delimited tokens, so they must not be flagged.
    data = {"tokenized": "a", "secrecy": "b", "passwordless": "c"}
    result = scan_for_secrets(data)
    assert result["detected_keys"] == []
    assert result["count"] == 0


def test_non_string_keys_do_not_crash() -> None:
    data = {1: "int", None: "none", ("a", "b"): "tuple"}
    result = scan_for_secrets(data)
    assert result["detected_keys"] == []
    assert result["count"] == 0


def test_sensitive_non_string_key_is_detected() -> None:
    # Numeric keys that normalize to a sensitive token should still be flagged.
    result = scan_for_secrets({"user_id": 5, "token": 123})
    assert result["detected_keys"] == ["token"]


def test_empty_and_primitive_inputs() -> None:
    for value in (None, {}, [], (), "string", 42, 0.0, True):
        result = scan_for_secrets(value)
        assert result["detected_keys"] == []
        assert result["count"] == 0


def test_string_value_does_not_get_walked() -> None:
    # String values must not be treated as containers of characters.
    result = scan_for_secrets({"header": "password is not a key here"})
    assert result["detected_keys"] == []
    assert result["count"] == 0
