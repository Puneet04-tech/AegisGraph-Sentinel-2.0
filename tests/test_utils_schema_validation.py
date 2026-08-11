import pytest

from src.utils.schema_validation import SchemaError, is_valid, validate

ACCOUNT_SCHEMA = {
    "account_id": {"type": "string", "required": True, "min_length": 4, "max_length": 20},
    "balance": {"type": "number", "required": True, "min": 0, "max": 100000},
    "currency": {"type": "string", "required": True, "enum": ["USD", "EUR", "GBP"]},
    "active": {"type": "boolean", "required": False},
    "tags": {
        "type": "list",
        "required": False,
        "items": {"type": "string", "min_length": 1, "max_length": 10},
    },
    "owner": {
        "type": "dict",
        "required": True,
        "properties": {
            "name": {"type": "string", "required": True},
            "age": {"type": "integer", "required": False, "min": 18, "max": 120},
        },
    },
}


def test_valid_data_passes():
    data = {
        "account_id": "AB1234",
        "balance": 250.5,
        "currency": "USD",
        "active": True,
        "tags": ["vip", "overseas"],
        "owner": {"name": "Ada", "age": 34},
    }
    assert validate(data, ACCOUNT_SCHEMA) is None


def test_string_shorthand_spec_is_required():
    schema = {"name": "string", "age": "integer"}
    assert validate({"name": "ada", "age": 30}, schema) is None
    with pytest.raises(SchemaError):
        validate({"age": 30}, schema)


def test_missing_required_field_raises():
    data = {"account_id": "AB1234", "balance": 10, "currency": "USD"}
    with pytest.raises(SchemaError) as exc_info:
        validate(data, ACCOUNT_SCHEMA)
    assert "owner" in exc_info.value.errors[0]


def test_wrong_type_error_mentions_field():
    data = {
        "account_id": "AB1234",
        "balance": "not-a-number",
        "currency": "USD",
        "owner": {"name": "Ada"},
    }
    with pytest.raises(SchemaError) as exc_info:
        validate(data, ACCOUNT_SCHEMA)
    assert any("balance" in msg and "number" in msg for msg in exc_info.value.errors)


def test_min_violation():
    schema = {"score": {"type": "number", "required": True, "min": 0}}
    with pytest.raises(SchemaError) as exc_info:
        validate({"score": -1}, schema)
    assert ">= 0" in exc_info.value.errors[0]


def test_max_violation():
    schema = {"score": {"type": "number", "required": True, "max": 100}}
    with pytest.raises(SchemaError) as exc_info:
        validate({"score": 150}, schema)
    assert "<= 100" in exc_info.value.errors[0]


def test_min_length_violation():
    schema = {"code": {"type": "string", "required": True, "min_length": 5}}
    with pytest.raises(SchemaError) as exc_info:
        validate({"code": "ab"}, schema)
    assert ">= 5" in exc_info.value.errors[0]


def test_max_length_violation():
    schema = {"code": {"type": "string", "required": True, "max_length": 5}}
    with pytest.raises(SchemaError) as exc_info:
        validate({"code": "abcdef"}, schema)
    assert "<= 5" in exc_info.value.errors[0]


def test_enum_membership_accepted():
    schema = {"currency": {"type": "string", "required": True, "enum": ["USD", "EUR"]}}
    assert validate({"currency": "USD"}, schema) is None


def test_enum_membership_rejected():
    schema = {"currency": {"type": "string", "required": True, "enum": ["USD", "EUR"]}}
    with pytest.raises(SchemaError) as exc_info:
        validate({"currency": "JPY"}, schema)
    assert "one of" in exc_info.value.errors[0]


def test_nested_list_items_validated():
    data = {
        "account_id": "AB1234",
        "balance": 10,
        "currency": "USD",
        "owner": {"name": "Ada"},
        "tags": ["vip", "this-tag-is-way-too-long"],
    }
    with pytest.raises(SchemaError) as exc_info:
        validate(data, ACCOUNT_SCHEMA)
    assert "tags[1]" in exc_info.value.errors[0]


def test_nested_list_item_wrong_type():
    data = {
        "account_id": "AB1234",
        "balance": 10,
        "currency": "USD",
        "owner": {"name": "Ada"},
        "tags": ["vip", 42],
    }
    with pytest.raises(SchemaError) as exc_info:
        validate(data, ACCOUNT_SCHEMA)
    assert "tags[1]" in exc_info.value.errors[0]


def test_nested_dict_properties_validated():
    data = {
        "account_id": "AB1234",
        "balance": 10,
        "currency": "USD",
        "owner": {"name": "Ada", "age": 12},
    }
    with pytest.raises(SchemaError) as exc_info:
        validate(data, ACCOUNT_SCHEMA)
    assert "owner.age" in exc_info.value.errors[0]


def test_nested_dict_missing_required_property():
    data = {
        "account_id": "AB1234",
        "balance": 10,
        "currency": "USD",
        "owner": {},
    }
    with pytest.raises(SchemaError) as exc_info:
        validate(data, ACCOUNT_SCHEMA)
    assert "owner.name" in exc_info.value.errors[0]


def test_optional_field_omitted_is_ok():
    schema = {
        "id": {"type": "string", "required": True},
        "nickname": {"type": "string", "required": False},
    }
    assert validate({"id": "a"}, schema) is None


def test_optional_field_omitted_nested_is_ok():
    data = {
        "account_id": "AB1234",
        "balance": 10,
        "currency": "USD",
        "owner": {"name": "Ada"},
    }
    assert validate(data, ACCOUNT_SCHEMA) is None


def test_is_valid_true_and_false():
    valid = {
        "account_id": "AB1234",
        "balance": 10,
        "currency": "USD",
        "owner": {"name": "Ada"},
    }
    assert is_valid(valid, ACCOUNT_SCHEMA) is True
    invalid = {
        "account_id": "AB1234",
        "balance": -5,
        "currency": "USD",
        "owner": {"name": "Ada"},
    }
    assert is_valid(invalid, ACCOUNT_SCHEMA) is False


def test_multiple_errors_collected_at_once():
    data = {
        "account_id": "x",
        "balance": -10,
        "currency": "JPY",
        "owner": {"name": "Ada"},
    }
    with pytest.raises(SchemaError) as exc_info:
        validate(data, ACCOUNT_SCHEMA)
    messages = exc_info.value.errors
    assert len(messages) == 3
    assert any("account_id" in msg for msg in messages)
    assert any("balance" in msg for msg in messages)
    assert any("currency" in msg for msg in messages)


def test_unknown_fields_ignored():
    schema = {"known": {"type": "string", "required": True}}
    data = {"known": "yes", "mystery": object(), "other": {"deep": 1}}
    assert validate(data, schema) is None


def test_number_accepts_int_and_float():
    schema = {"amount": {"type": "number", "required": True}}
    assert validate({"amount": 5}, schema) is None
    assert validate({"amount": 5.75}, schema) is None


def test_integer_rejects_float():
    schema = {"age": {"type": "integer", "required": True}}
    assert validate({"age": 30}, schema) is None
    with pytest.raises(SchemaError) as exc_info:
        validate({"age": 30.5}, schema)
    assert "integer" in exc_info.value.errors[0]


def test_number_rejects_boolean():
    schema = {"amount": {"type": "number", "required": True}}
    with pytest.raises(SchemaError):
        validate({"amount": True}, schema)


def test_schema_error_errors_list_accessible():
    schema = {"a": {"type": "string", "required": True}}
    try:
        validate({}, schema)
        pytest.fail("expected SchemaError")
    except SchemaError as exc:
        assert isinstance(exc.errors, list)
        assert "a" in exc.errors[0]


def test_any_type_accepts_everything():
    schema = {"payload": {"type": "any", "required": True}}
    for value in [1, "x", 2.5, True, [1], {"k": "v"}, None]:
        assert validate({"payload": value}, schema) is None


def test_root_non_dict_raises():
    with pytest.raises(SchemaError) as exc_info:
        validate([1, 2], {"anything": "any"})
    assert "root" in exc_info.value.errors[0]
