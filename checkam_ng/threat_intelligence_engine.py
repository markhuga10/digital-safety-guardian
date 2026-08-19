from checkam_ng.fraud_taxonomy import FraudCategory
from checkam_ng.threat_intelligence import (
    CommunicationChannel,
    ConfidenceLevel,
    ThreatIntelligence,
)


def _categories(findings):
    """
    Extract detection categories from findings.
    """

    if not findings:
        return set()

    return {
        finding.get("category")
        for finding in findings
        if isinstance(finding, dict)
        and isinstance(finding.get("category"), str)
    }


def _detect_channel(message):
    """
    Estimate the communication channel from message content.

    This is intentionally conservative. If the channel cannot
    be reasonably inferred, OTHER is returned.
    """

    if not isinstance(message, str):
        return CommunicationChannel.OTHER

    text = message.lower()

    if any(
        keyword in text
        for keyword in [
            "whatsapp",
            "whats app",
        ]
    ):
        return CommunicationChannel.WHATSAPP

    if any(
        keyword in text
        for keyword in [
            "sms",
            "text message",
            "texted you",
        ]
    ):
        return CommunicationChannel.SMS

    if any(
        keyword in text
        for keyword in [
            "email",
            "e-mail",
            "mailbox",
        ]
    ):
        return CommunicationChannel.EMAIL

    if any(
        keyword in text
        for keyword in [
            "call me",
            "phone call",
            "calling you",
        ]
    ):
        return CommunicationChannel.PHONE

    if any(
        keyword in text
        for keyword in [
            "instagram",
            "facebook",
            "twitter",
            "x.com",
            "social media",
        ]
    ):
        return CommunicationChannel.SOCIAL_MEDIA

    if any(
        keyword in text
        for keyword in [
            "website",
            "web page",
            "webpage",
            "visit this site",
        ]
    ):
        return CommunicationChannel.WEBSITE

    return CommunicationChannel.OTHER


def _detect_impersonated_entity(
    message,
    fraud_category,
):
    """
    Estimate the entity being impersonated.
    """

    text = message.lower() if isinstance(message, str) else ""

    if fraud_category == FraudCategory.BANKING_FRAUD:

        if "gtbank" in text or "guaranty trust" in text:
            return "GTBank"

        if "access bank" in text:
            return "Access Bank"

        if "first bank" in text:
            return "FirstBank"

        if "uba" in text:
            return "UBA"

        if "zenith" in text:
            return "Zenith Bank"

        if "opay" in text:
            return "OPay"

        if "moniepoint" in text:
            return "Moniepoint"

        return "Bank"

    if fraud_category == FraudCategory.MOBILE_MONEY_SCAM:

        if "opay" in text:
            return "OPay"

        if "moniepoint" in text:
            return "Moniepoint"

        if "palmpay" in text:
            return "PalmPay"

        if "paga" in text:
            return "Paga"

        return "Mobile Money Service"

    if fraud_category == FraudCategory.CRYPTO_SCAM:
        return "Cryptocurrency / Digital Asset Service"

    if fraud_category == FraudCategory.INVESTMENT_SCAM:
        return "Investment Service"

    if fraud_category == FraudCategory.JOB_SCAM:
        return "Employer / Recruitment Service"

    if fraud_category == FraudCategory.DELIVERY_SCAM:
        return "Delivery / Courier Service"

    if fraud_category == FraudCategory.ROMANCE_SCAM:
        return "Online Contact"

    if fraud_category == FraudCategory.LOTTERY_SCAM:
        return "Lottery / Prize Organization"

    if fraud_category == FraudCategory.IMPERSONATION:
        return "Unknown Entity"

    return "Unknown Entity"


def _detect_target(
    message,
    fraud_category,
):
    """
    Determine the likely target of the fraud attempt.
    """

    text = message.lower() if isinstance(message, str) else ""

    if fraud_category in {
        FraudCategory.BANKING_FRAUD,
        FraudCategory.CREDENTIAL_PHISHING,
    }:
        return "Account credentials"

    if fraud_category == FraudCategory.ACCOUNT_TAKEOVER:
        return "User account"

    if fraud_category in {
        FraudCategory.PAYMENT_SCAM,
        FraudCategory.MOBILE_MONEY_SCAM,
    }:
        return "Money or payment account"

    if fraud_category == FraudCategory.CRYPTO_SCAM:
        return "Cryptocurrency or digital assets"

    if fraud_category == FraudCategory.INVESTMENT_SCAM:
        return "Money or investment funds"

    if fraud_category == FraudCategory.JOB_SCAM:
        return "Job seeker / personal information"

    if fraud_category == FraudCategory.DELIVERY_SCAM:
        return "Payment information or personal information"

    if fraud_category == FraudCategory.ROMANCE_SCAM:
        return "Money or personal information"

    if fraud_category == FraudCategory.LOTTERY_SCAM:
        return "Money or personal information"

    if fraud_category == FraudCategory.IMPERSONATION:
        return "Personal information or money"

    if text:
        return "Message recipient"

    return "Unknown"


def _detect_requested_action(
    message,
    categories,
):
    """
    Determine what the victim is being asked to do.
    """

    text = message.lower() if isinstance(message, str) else ""

    if "credential_request" in categories:
        return "Provide credentials or verification information"

    if "payment_request" in categories:
        return "Send money or make a payment"

    if "threat_language" in categories:
        if "click" in text or "link" in text:
            return "Click a link or complete the requested verification"

        return "Take immediate action under pressure"

    if "impersonation" in categories:
        return "Trust or respond to the impersonating entity"

    if "urgency" in categories:
        return "Act immediately"

    return "No specific action identified"


def _detect_likely_impact(fraud_category):
    """
    Describe the likely impact if the victim follows
    the attacker's instructions.
    """

    impacts = {
        FraudCategory.BANKING_FRAUD:
            "Bank account compromise and financial loss",

        FraudCategory.PAYMENT_SCAM:
            "Financial loss",

        FraudCategory.CREDENTIAL_PHISHING:
            "Credential theft and account compromise",

        FraudCategory.ACCOUNT_TAKEOVER:
            "Unauthorized account access and identity abuse",

        FraudCategory.IMPERSONATION:
            "Identity abuse, financial loss, or information theft",

        FraudCategory.INVESTMENT_SCAM:
            "Financial loss and fraudulent investment activity",

        FraudCategory.JOB_SCAM:
            "Financial loss or theft of personal information",

        FraudCategory.DELIVERY_SCAM:
            "Financial loss or payment information theft",

        FraudCategory.ROMANCE_SCAM:
            "Financial loss and emotional exploitation",

        FraudCategory.MOBILE_MONEY_SCAM:
            "Unauthorized mobile-money transactions and financial loss",

        FraudCategory.CRYPTO_SCAM:
            "Cryptocurrency theft and financial loss",

        FraudCategory.LOTTERY_SCAM:
            "Financial loss and personal information theft",

        FraudCategory.UNKNOWN:
            "Potential financial or information loss",
    }

    return impacts.get(
        fraud_category,
        "Potential financial or information loss",
    )


def _determine_confidence(
    fraud_category,
    message_categories,
    url_categories,
):
    """
    Estimate confidence based on the amount of supporting
    evidence available.
    """

    if fraud_category == FraudCategory.UNKNOWN:
        return ConfidenceLevel.LOW

    evidence_count = (
        len(message_categories)
        + len(url_categories)
    )

    if evidence_count >= 3:
        return ConfidenceLevel.HIGH

    if evidence_count >= 2:
        return ConfidenceLevel.MEDIUM

    return ConfidenceLevel.LOW


def _build_evidence(
    message_categories,
    url_categories,
):
    """
    Convert detection categories into human-readable evidence.
    """

    evidence = []

    descriptions = {
        "urgency": "Urgency or pressure to act quickly",
        "credential_request": "Request for credentials or verification information",
        "payment_request": "Request for money, payment, or transfer",
        "threat_language": "Threatening or intimidating language",
        "impersonation": "Possible impersonation of a trusted entity",
        "social_engineering": "Social-engineering indicators",
        "insecure_protocol": "URL uses an insecure HTTP connection",
        "ip_address_host": "URL uses an IP address instead of a normal domain",
        "suspicious_keyword": "URL contains a suspicious keyword",
        "lookalike_domain": "URL appears to use a lookalike domain",
        "embedded_credentials": "URL contains embedded credentials",
        "excessive_subdomains": "URL contains an unusual number of subdomains",
    }

    for category in sorted(
        message_categories | url_categories
    ):
        evidence.append(
            descriptions.get(
                category,
                f"Detected indicator: {category}",
            )
        )

    return evidence


def generate_threat_intelligence(
    message_findings,
    url_findings,
    fraud_category,
    message="",
):
    """
    Generate structured ThreatIntelligence from an existing
    CheckAm-NG analysis.

    Args:
        message_findings: Findings produced by the message detector.
        url_findings: Findings produced by the URL detector.
        fraud_category: FraudCategory returned by the classifier.
        message: Original message being analyzed.

    Returns:
        ThreatIntelligence
    """

    if not isinstance(fraud_category, FraudCategory):
        raise TypeError(
            "fraud_category must be a FraudCategory"
        )

    message_categories = _categories(
        message_findings
    )

    url_categories = _categories(
        url_findings
    )

    all_categories = (
        message_categories | url_categories
    )

    channel = _detect_channel(message)

    impersonated_entity = _detect_impersonated_entity(
        message,
        fraud_category,
    )

    target = _detect_target(
        message,
        fraud_category,
    )

    requested_action = _detect_requested_action(
        message,
        all_categories,
    )

    likely_impact = _detect_likely_impact(
        fraud_category,
    )

    confidence = _determine_confidence(
        fraud_category,
        message_categories,
        url_categories,
    )

    evidence = _build_evidence(
        message_categories,
        url_categories,
    )

    return ThreatIntelligence(
        impersonated_entity=impersonated_entity,
        fraud_type=fraud_category,
        target=target,
        communication_channel=channel,
        requested_action=requested_action,
        likely_impact=likely_impact,
        confidence=confidence,
        evidence=evidence,
    )
