"""Unit tests for PII masking utilities"""

import pytest

from src.utils.pii_masking import (
    mask_card_number,
    mask_email,
    mask_generic,
    mask_payload,
    mask_phone,
    mask_ssn,
)


@pytest.mark.parametrize(
    "email,expected",
    [
        ("john.doe@example.com", "j*******@example.com"),
        ("jane@example.com", "j***@example.com"),
        ("user.name+tag@sub.example.co.uk", "u************@sub.example.co.uk"),
        ("a@example.com", "a@example.com"),
        ("JOHN@EXAMPLE.COM", "J***@EXAMPLE.COM"),
    ],
)
def test_mask_email_valid(email, expected):
    assert mask_email(email) == expected


@pytest.mark.parametrize(
    "email",
    [
        "",
        None,
        "not-an-email",
        "missing-at-sign",
        "a@",
        "@example.com",
        "a@b",
        "user@@example.com",
        12345,
    ],
)
def test_mask_email_invalid_unchanged(email):
    assert mask_email(email) == email


@pytest.mark.parametrize(
    "phone,expected",
    [
        ("+1-555-123-4521", "+1-XXX-XXX-4521"),
        ("555-123-4521", "XXX-XXX-4521"),
        ("1234567890", "XXXXXX7890"),
        ("+91 98765 43210", "+91 XXXXX X3210"),
        ("4521", "4521"),
        ("911", "911"),
        ("", ""),
        (None, None),
    ],
)
def test_mask_phone(phone, expected):
    assert mask_phone(phone) == expected


@pytest.mark.parametrize(
    "card,expected",
    [
        ("1234-5678-9012-3456", "XXXX-XXXX-XXXX-3456"),
        ("4111111111111111", "XXXXXXXXXXXX1111"),
        ("1234-5678-9012", "XXXX-XXXX-9012"),
        ("1234", "1234"),
        ("", ""),
        (None, None),
    ],
)
def test_mask_card_number(card, expected):
    assert mask_card_number(card) == expected


@pytest.mark.parametrize(
    "ssn,expected",
    [
        ("123-45-6789", "XXX-XX-6789"),
        ("987-65-4321", "XXX-XX-4321"),
        ("12-34-5678", "XX-XX-5678"),
        ("123456789", "XXXXX6789"),
        ("", ""),
        (None, None),
    ],
)
def test_mask_ssn(ssn, expected):
    assert mask_ssn(ssn) == expected


@pytest.mark.parametrize(
    "value,keep_first,keep_last,expected",
    [
        ("hello world", 2, 2, "he*******ld"),
        ("abcde", 2, 2, "ab*de"),
        ("abcdef", 2, 2, "ab**ef"),
        ("hello world", 1, 1, "h*********d"),
        ("1234567890123456", 2, 2, "12************56"),
    ],
)
def test_mask_generic_masks_middle(value, keep_first, keep_last, expected):
    assert mask_generic(value, keep_first=keep_first, keep_last=keep_last) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("ab", "ab"),
        ("abc", "abc"),
        ("abcd", "abcd"),
        ("", ""),
        (None, None),
        (42, 42),
    ],
)
def test_mask_generic_short_or_invalid_unchanged(value, expected):
    assert mask_generic(value) == expected


def test_mask_payload_nested_dict():
    payload = {
        "email": "john.doe@example.com",
        "phone": "+1-555-123-4521",
        "card_number": "1234-5678-9012-3456",
        "ssn": "123-45-6789",
        "name": "John Doe",
        "amount": 100,
        "nested": {
            "email": "jane@example.com",
            "card": "4111111111111111",
            "pan": "9876543210987654",
            "notes": "hello",
        },
    }
    masked = mask_payload(payload)
    assert masked["email"] == "j*******@example.com"
    assert masked["phone"] == "+1-XXX-XXX-4521"
    assert masked["card_number"] == "XXXX-XXXX-XXXX-3456"
    assert masked["ssn"] == "XXX-XX-6789"
    assert masked["name"] == "John Doe"
    assert masked["amount"] == 100
    assert masked["nested"]["email"] == "j***@example.com"
    assert masked["nested"]["card"] == "XXXXXXXXXXXX1111"
    assert masked["nested"]["pan"] == "XXXXXXXXXXXX7654"
    assert masked["nested"]["notes"] == "hello"


def test_mask_payload_list_of_dicts():
    payload = {
        "customers": [
            {"email": "a@example.com", "phone": "555-1212", "id": 1},
            {"email": "b@example.org", "phone": "555-3434", "id": 2},
        ]
    }
    masked = mask_payload(payload)
    assert masked["customers"][0] == {
        "email": "a@example.com",
        "phone": "XXX-1212",
        "id": 1,
    }
    assert masked["customers"][1] == {
        "email": "b@example.org",
        "phone": "XXX-3434",
        "id": 2,
    }


def test_mask_payload_does_not_mutate_original():
    payload = {
        "email": "john.doe@example.com",
        "phone": "+1-555-123-4521",
        "nested": {"card_number": "1234-5678-9012-3456"},
    }
    original = {
        "email": "john.doe@example.com",
        "phone": "+1-555-123-4521",
        "nested": {"card_number": "1234-5678-9012-3456"},
    }
    result = mask_payload(payload)
    assert payload == original
    assert result is not payload
    assert result["nested"] is not payload["nested"]


def test_mask_payload_case_insensitive_keys():
    payload = {"EMAIL": "JOHN@EXAMPLE.COM", "Phone": "+1-555-123-4521"}
    masked = mask_payload(payload)
    assert masked["EMAIL"] == "J***@EXAMPLE.COM"
    assert masked["Phone"] == "+1-XXX-XXX-4521"


def test_mask_payload_non_pii_keys_and_values_preserved():
    payload = {
        "tags": ["a", "b"],
        "count": 5,
        "active": True,
        "meta": {"nested_list": [1, 2, 3]},
        "email": None,
    }
    masked = mask_payload(payload)
    assert masked["tags"] == ["a", "b"]
    assert masked["count"] == 5
    assert masked["active"] is True
    assert masked["meta"] == {"nested_list": [1, 2, 3]}
    assert masked["email"] is None


def test_mask_payload_deep_nesting():
    payload = {"a": {"b": {"c": {"email": "deep@example.com", "keep": "x"}}}}
    masked = mask_payload(payload)
    assert masked["a"]["b"]["c"]["email"] == "d***@example.com"
    assert masked["a"]["b"]["c"]["keep"] == "x"
