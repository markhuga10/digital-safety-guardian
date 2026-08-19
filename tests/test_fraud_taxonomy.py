import pytest

from checkam_ng.fraud_taxonomy import (
    FraudCategory,
    get_fraud_category,
)


def test_all_core_fraud_categories_exist():
    expected_categories = {
        "banking_fraud",
        "payment_scam",
        "credential_phishing",
        "account_takeover",
        "impersonation",
        "investment_scam",
        "job_scam",
        "delivery_scam",
        "romance_scam",
        "mobile_money_scam",
        "crypto_scam",
    }

    actual_categories = {
        category.value
        for category in FraudCategory
    }

    assert expected_categories.issubset(actual_categories)


def test_banking_fraud_category_exists():
    assert (
        FraudCategory.BANKING_FRAUD.value
        == "banking_fraud"
    )


def test_mobile_money_scam_category_exists():
    assert (
        FraudCategory.MOBILE_MONEY_SCAM.value
        == "mobile_money_scam"
    )


def test_crypto_scam_category_exists():
    assert (
        FraudCategory.CRYPTO_SCAM.value
        == "crypto_scam"
    )


def test_get_fraud_category_returns_enum():
    category = get_fraud_category("payment_scam")

    assert category == FraudCategory.PAYMENT_SCAM


def test_get_fraud_category_rejects_unknown_category():
    with pytest.raises(ValueError):
        get_fraud_category("unknown_scam")


def test_get_fraud_category_rejects_empty_value():
    with pytest.raises(ValueError):
        get_fraud_category("")


def test_fraud_categories_are_unique():
    values = [
        category.value
        for category in FraudCategory
    ]

    assert len(values) == len(set(values))
