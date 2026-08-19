from checkam_ng.fraud_taxonomy import FraudCategory


def _categories(findings):
    """Extract valid category names from detection findings."""

    if not findings:
        return set()

    return {
        finding.get("category")
        for finding in findings
        if isinstance(finding, dict)
        and isinstance(finding.get("category"), str)
    }


def classify_fraud(
    message_findings,
    url_findings,
    message="",
):
    """
    Classify detected activity into a CheckAm-NG fraud category.

    This function classifies the type of suspected fraud.
    Risk scoring remains handled by the existing risk engines.
    """

    message_categories = _categories(message_findings)
    url_categories = _categories(url_findings)

    all_categories = message_categories | url_categories

    text = message.lower() if isinstance(message, str) else ""

    # Account takeover has priority over generic credential phishing.
    if (
        "credential_request" in all_categories
        and "threat_language" in all_categories
    ):
        return FraudCategory.ACCOUNT_TAKEOVER

    # Crypto-related payment requests.
    crypto_keywords = {
        "bitcoin",
        "btc",
        "ethereum",
        "eth",
        "crypto",
        "cryptocurrency",
        "wallet",
        "usdt",
        "blockchain",
    }

    if (
        "payment_request" in all_categories
        and any(keyword in text for keyword in crypto_keywords)
    ):
        return FraudCategory.CRYPTO_SCAM

    # Mobile-money payment scams.
    mobile_money_keywords = {
        "mobile money",
        "mobile-money",
        "momo",
        "moniepoint",
        "opay",
        "paga",
        "palmpay",
        "transfer pin",
        "transaction pin",
    }

    if (
        "payment_request" in all_categories
        and any(keyword in text for keyword in mobile_money_keywords)
    ):
        return FraudCategory.MOBILE_MONEY_SCAM

    # Banking credential theft.
    banking_keywords = {
        "bank",
        "banking",
        "account number",
        "account details",
        "atm",
        "debit card",
        "credit card",
        "bank account",
        "internet banking",
        "online banking",
    }

    if (
        "credential_request" in all_categories
        and any(keyword in text for keyword in banking_keywords)
    ):
        return FraudCategory.BANKING_FRAUD

    # Generic credential phishing.
    if "credential_request" in all_categories:
        return FraudCategory.CREDENTIAL_PHISHING

    # Generic payment scam.
    if "payment_request" in all_categories:
        return FraudCategory.PAYMENT_SCAM

    # Impersonation.
    if "impersonation" in all_categories:
        return FraudCategory.IMPERSONATION

    # Nothing sufficiently specific detected.
    return FraudCategory.UNKNOWN
