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


def test_compound_sensitive_keys() -> None:
    # Compound tokens (client_secret, refresh_token, auth_token) are flagged.
    result = scan_for_secrets(
        {"auth_token": "a", "client_secret": "b", "refresh_token": "c"}
    )
    assert result["count"] == 3
    assert set(result["detected_keys"]) == {
        "auth_token",
        "client_secret",
        "refresh_token",
    }


def test_single_token_variants() -> None:
    # Any underscore-delimited part matching a sensitive single token counts.
    result = scan_for_secrets(
        {"my_token": "a", "token_v2": "b", "Bearer-Token": "c", "x_password": "d"}
    )
    assert result["count"] == 4


def test_plural_and_substring_forms_not_flagged() -> None:
    # "secrets"/"tokens"/"tokenless" are not the sensitive singular tokens.
    result = scan_for_secrets({"secrets": "a", "tokens": "b", "tokenless": "c"})
    assert result["detected_keys"] == []
    assert result["count"] == 0


def test_deep_mixed_nesting() -> None:
    # dict -> list -> tuple -> dict keeps finding sensitive keys at any depth.
    data = {"outer": [{"inner": ("x", {"api_key": "k"})}]}
    result = scan_for_secrets(data)
    assert result["detected_keys"] == ["api_key"]
    assert result["count"] == 1


def test_detection_order_is_depth_first() -> None:
    data = {"a": {"token": "1"}, "password": "2", "b": {"secret": "3"}}
    result = scan_for_secrets(data)
    assert result["detected_keys"] == ["token", "password", "secret"]


def test_sensitive_key_with_container_value() -> None:
    # A sensitive key still matches when its value is itself a container.
    data = {"password": {"nested": {"secret": "s"}}}
    result = scan_for_secrets(data)
    assert result["detected_keys"] == ["password", "secret"]


def test_realistic_config_payload() -> None:
    # Only genuinely sensitive fields in a large payload are flagged.
    data = {
        "service": "fraud-engine",
        "environment": "prod",
        "clients": [
            {"name": "alpha", "public_key": "pub-123"},
            {"name": "beta", "api_key": "k"},
        ],
        "notifications": {"email": "ops@example.com"},
    }
    result = scan_for_secrets(data)
    assert result["detected_keys"] == ["api_key"]
    assert result["count"] == 1


def test_sets_are_not_traversed() -> None:
    # Sets are treated as leaf values by the scanner (documented behavior).
    result = scan_for_secrets({"tags": {"token"}})
    assert result["detected_keys"] == []
    assert result["count"] == 0


def test_uppercase_and_space_variants() -> None:
    result = scan_for_secrets({"API KEY": "a", "PASSWORD": "b", "Connection String": "c"})
    assert result["count"] == 3
