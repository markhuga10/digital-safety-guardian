import pytest

from checkam_ng.fraud_classifier import classify_fraud
from checkam_ng.fraud_taxonomy import FraudCategory


def test_credential_phishing_is_classified():
    result = classify_fraud(
        message_findings=[
            {"category": "credential_request"},
            {"category": "urgency"},
        ],
        url_findings=[
            {"category": "suspicious_keyword"},
        ],
    )

    assert result == FraudCategory.CREDENTIAL_PHISHING


def test_payment_scam_is_classified():
    result = classify_fraud(
        message_findings=[
            {"category": "payment_request"},
            {"category": "urgency"},
        ],
        url_findings=[],
    )

    assert result == FraudCategory.PAYMENT_SCAM


def test_impersonation_is_classified():
    result = classify_fraud(
        message_findings=[
            {"category": "impersonation"},
        ],
        url_findings=[],
    )

    assert result == FraudCategory.IMPERSONATION


def test_account_takeover_is_classified():
    result = classify_fraud(
        message_findings=[
            {"category": "credential_request"},
            {"category": "threat_language"},
        ],
        url_findings=[],
    )

    assert result == FraudCategory.ACCOUNT_TAKEOVER


def test_crypto_scam_is_classified():
    result = classify_fraud(
        message_findings=[
            {"category": "payment_request"},
        ],
        url_findings=[
            {"category": "suspicious_keyword"},
        ],
        message="Send bitcoin immediately to verify your wallet",
    )

    assert result == FraudCategory.CRYPTO_SCAM


def test_banking_fraud_is_classified():
    result = classify_fraud(
        message_findings=[
            {"category": "credential_request"},
        ],
        url_findings=[],
        message="Your bank account has been suspended. Verify your banking details.",
    )

    assert result == FraudCategory.BANKING_FRAUD


def test_mobile_money_scam_is_classified():
    result = classify_fraud(
        message_findings=[
            {"category": "payment_request"},
        ],
        url_findings=[],
        message="Your mobile money account requires urgent payment verification.",
    )

    assert result == FraudCategory.MOBILE_MONEY_SCAM


def test_no_findings_returns_unknown():
    result = classify_fraud(
        message_findings=[],
        url_findings=[],
        message="Hello, how are you today?",
    )

    assert result == FraudCategory.UNKNOWN
