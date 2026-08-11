"""Unit tests for the predictive mule scoring features.

These tests pin the email-domain risk scoring: temporary and free email
providers must be recognised by their actual domain (including subdomains),
and lookalike domains that merely *contain* a provider name must not be
misclassified.
"""

import pytest

from src.features.predictive_mule_identification import PredictiveMuleScorer


@pytest.fixture()
def scorer():
    return PredictiveMuleScorer()


def _email_risk(scorer, email):
    result = scorer.score_account_opening(
        name="test",
        age=25,
        profession="engineer",
        stated_address="Mumbai",
        email=email,
        phone="9876543210",
        document_type="Aadhaar",
        facial_match=0.95,
        document_quality_score=0.95,
        ip_address="10.0.0.1",
        device_id="DEV1",
        device_age_days=100,
        browser_fingerprint="fp",
        initial_deposit=5000.0,
        account_type="savings",
        referral=None,
        existing_customer_connections=5,
    )
    return result["email_risk"]


def test_exact_temp_domain_scores_high(scorer):
    assert _email_risk(scorer, "abc@mailinator.com") == 90.0


def test_subdomain_of_temp_domain_scores_high(scorer):
    assert _email_risk(scorer, "abc@mail.guerrillamail.com") == 90.0


def test_temp_domain_with_trailing_dot_is_normalized(scorer):
    assert _email_risk(scorer, "abc@tempmail.com.") == 90.0


def test_lookalike_domain_containing_temp_substring_is_not_flagged(scorer):
    assert _email_risk(scorer, "abc@notmailinator.com") == 10.0


def test_lookalike_domain_with_temp_prefix_is_not_flagged(scorer):
    assert _email_risk(scorer, "abc@tempmail-services.com") == 10.0


def test_uppercase_temp_domain_is_still_flagged(scorer):
    assert _email_risk(scorer, "ABC@MAILINATOR.COM") == 90.0


def test_exact_free_domain_scores_low(scorer):
    assert _email_risk(scorer, "user@gmail.com") == 20.0


def test_subdomain_of_free_domain_scores_low(scorer):
    assert _email_risk(scorer, "user@mail.gmail.com") == 20.0


def test_free_domain_lookalike_is_not_whitelisted(scorer):
    assert _email_risk(scorer, "user@gmail.com.attacker.io") == 10.0


def test_free_domain_prefix_lookalike_is_not_whitelisted(scorer):
    assert _email_risk(scorer, "user@notgmail.com") == 10.0


def test_corporate_domain_scores_low(scorer):
    assert _email_risk(scorer, "user@acme-corp.example") == 10.0


def test_email_without_at_sign_scores_low(scorer):
    assert _email_risk(scorer, "not-an-email") == 10.0


def test_other_temp_domains_score_high(scorer):
    assert _email_risk(scorer, "abc@10minutemail.com") == 90.0
    assert _email_risk(scorer, "abc@throwaway.email") == 90.0
    assert _email_risk(scorer, "abc@maildrop.cc") == 90.0
    assert _email_risk(scorer, "abc@sub.maildrop.cc") == 90.0


def test_other_free_domains_score_low(scorer):
    assert _email_risk(scorer, "user@yahoo.com") == 20.0
    assert _email_risk(scorer, "user@outlook.com") == 20.0
    assert _email_risk(scorer, "user@hotmail.com") == 20.0
    assert _email_risk(scorer, "user@mail.hotmail.com") == 20.0


def test_email_with_surrounding_whitespace(scorer):
    assert _email_risk(scorer, "  abc@mailinator.com  ") == 90.0
    assert _email_risk(scorer, " user@gmail.com ") == 20.0


def test_empty_and_whitespace_only_email(scorer):
    assert _email_risk(scorer, "") == 10.0
    assert _email_risk(scorer, "   ") == 10.0


def _phone_risk(scorer, phone_age_days=None, phone="9876543210"):
    kwargs = dict(
        name="test",
        age=25,
        profession="engineer",
        stated_address="Mumbai",
        email="user@acme-corp.example",
        phone=phone,
        document_type="Aadhaar",
        facial_match=0.95,
        document_quality_score=0.95,
        ip_address="10.0.0.1",
        device_id="DEV1",
        device_age_days=100,
        browser_fingerprint="fp",
        initial_deposit=5000.0,
        account_type="savings",
        referral=None,
        existing_customer_connections=5,
    )
    if phone_age_days is not None:
        kwargs["phone_age_days"] = phone_age_days
    result = scorer.score_account_opening(**kwargs)
    return result["phone_risk"]


def test_phone_age_missing_returns_neutral_zero(scorer):
    assert _phone_risk(scorer) == 0.0
    # Different numbers must not invent different simulated risk
    assert _phone_risk(scorer, phone="1111111111") == 0.0
    assert _phone_risk(scorer, phone="9999999999") == 0.0


def test_phone_age_days_scores_from_real_value(scorer):
    assert _phone_risk(scorer, phone_age_days=3) == 85.0
    assert _phone_risk(scorer, phone_age_days=15) == 60.0
    assert _phone_risk(scorer, phone_age_days=45) == 35.0
    assert _phone_risk(scorer, phone_age_days=120) == 10.0
