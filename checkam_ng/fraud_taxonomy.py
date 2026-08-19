from enum import Enum


class FraudCategory(str, Enum):
    """
    Fraud categories recognized by CheckAm-NG.
    """

    BANKING_FRAUD = "banking_fraud"
    PAYMENT_SCAM = "payment_scam"
    CREDENTIAL_PHISHING = "credential_phishing"
    ACCOUNT_TAKEOVER = "account_takeover"
    IMPERSONATION = "impersonation"
    INVESTMENT_SCAM = "investment_scam"
    JOB_SCAM = "job_scam"
    DELIVERY_SCAM = "delivery_scam"
    ROMANCE_SCAM = "romance_scam"
    MOBILE_MONEY_SCAM = "mobile_money_scam"
    CRYPTO_SCAM = "crypto_scam"
    LOTTERY_SCAM = "lottery_scam"
    UNKNOWN = "unknown"


def get_fraud_category(value: str) -> FraudCategory:
    """
    Convert a string into a FraudCategory enum.

    Raises:
        TypeError: If value is not a string.
        ValueError: If value is empty or unknown.
    """

    if not isinstance(value, str):
        raise TypeError("fraud category must be a string")

    value = value.strip().lower()

    if not value:
        raise ValueError("fraud category cannot be empty")

    try:
        return FraudCategory(value)
    except ValueError as exc:
        raise ValueError(
            f"Unknown fraud category: {value}"
        ) from exc
