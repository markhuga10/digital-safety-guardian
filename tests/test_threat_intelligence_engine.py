import pytest

from checkam_ng.fraud_taxonomy import FraudCategory
from checkam_ng.threat_intelligence import (
    CommunicationChannel,
    ConfidenceLevel,
    ThreatIntelligence,
)
from checkam_ng.threat_intelligence_engine import (
    generate_threat_intelligence,
)


def test_generates_threat_intelligence_for_banking_fraud():

    message_findings = [
        {
            "category": "credential_request",
            "pattern": "otp",
            "description": "Requests account verification information",
        },
        {
            "category": "urgency",
            "pattern": "urgent",
            "description": "Creates pressure to act quickly",
        },
    ]

    url_findings = [
        {
            "category": "insecure_protocol",
            "pattern": "http",
            "description": "URL uses HTTP",
        }
    ]

    intelligence = generate_threat_intelligence(
        message_findings=message_findings,
        url_findings=url_findings,
        fraud_category=FraudCategory.BANKING_FRAUD,
        message="URGENT! Your bank account needs verification. Click the link.",
    )

    assert isinstance(
        intelligence,
        ThreatIntelligence,
    )

    assert (
        intelligence.fraud_type
        == FraudCategory.BANKING_FRAUD
    )

    assert intelligence.impersonated_entity == "Bank"

    assert intelligence.target == "Account credentials"

    assert (
        intelligence.requested_action
        == "Provide credentials or verification information"
    )

    assert (
        intelligence.likely_impact
        == "Bank account compromise and financial loss"
    )

    assert (
        intelligence.confidence
        == ConfidenceLevel.HIGH
    )

    assert (
        intelligence.communication_channel
        == CommunicationChannel.OTHER
    )

    assert intelligence.evidence


def test_detects_whatsapp_channel():

    intelligence = generate_threat_intelligence(
        message_findings=[
            {
                "category": "payment_request",
                "pattern": "send money",
            }
        ],
        url_findings=[],
        fraud_category=FraudCategory.PAYMENT_SCAM,
        message="Send the money through WhatsApp immediately.",
    )

    assert (
        intelligence.communication_channel
        == CommunicationChannel.WHATSAPP
    )


def test_detects_sms_channel():

    intelligence = generate_threat_intelligence(
        message_findings=[
            {
                "category": "payment_request",
            }
        ],
        url_findings=[],
        fraud_category=FraudCategory.PAYMENT_SCAM,
        message="This SMS requires you to send money immediately.",
    )

    assert (
        intelligence.communication_channel
        == CommunicationChannel.SMS
    )


def test_detects_email_channel():

    intelligence = generate_threat_intelligence(
        message_findings=[
            {
                "category": "credential_request",
            }
        ],
        url_findings=[],
        fraud_category=FraudCategory.CREDENTIAL_PHISHING,
        message="This email asks you to verify your account.",
    )

    assert (
        intelligence.communication_channel
        == CommunicationChannel.EMAIL
    )


def test_detects_mobile_money_entity():

    intelligence = generate_threat_intelligence(
        message_findings=[
            {
                "category": "payment_request",
            }
        ],
        url_findings=[],
        fraud_category=FraudCategory.MOBILE_MONEY_SCAM,
        message="Your Moniepoint account requires an urgent transfer.",
    )

    assert (
        intelligence.impersonated_entity
        == "Moniepoint"
    )

    assert (
        intelligence.fraud_type
        == FraudCategory.MOBILE_MONEY_SCAM
    )


def test_detects_crypto_scam():

    intelligence = generate_threat_intelligence(
        message_findings=[
            {
                "category": "payment_request",
            }
        ],
        url_findings=[],
        fraud_category=FraudCategory.CRYPTO_SCAM,
        message="Send bitcoin to this wallet immediately.",
    )

    assert (
        intelligence.fraud_type
        == FraudCategory.CRYPTO_SCAM
    )

    assert (
        intelligence.impersonated_entity
        == "Cryptocurrency / Digital Asset Service"
    )

    assert (
        intelligence.target
        == "Cryptocurrency or digital assets"
    )


def test_unknown_category_has_low_confidence():

    intelligence = generate_threat_intelligence(
        message_findings=[],
        url_findings=[],
        fraud_category=FraudCategory.UNKNOWN,
        message="Hello, how are you?",
    )

    assert (
        intelligence.fraud_type
        == FraudCategory.UNKNOWN
    )

    assert (
        intelligence.confidence
        == ConfidenceLevel.LOW
    )

    assert intelligence.impersonated_entity == "Unknown Entity"


def test_invalid_fraud_category_is_rejected():

    with pytest.raises(TypeError):

        generate_threat_intelligence(
            message_findings=[],
            url_findings=[],
            fraud_category="payment_scam",
            message="Send money immediately.",
        )


def test_evidence_contains_detection_indicators():

    intelligence = generate_threat_intelligence(
        message_findings=[
            {
                "category": "urgency",
            },
            {
                "category": "payment_request",
            },
        ],
        url_findings=[
            {
                "category": "suspicious_keyword",
            }
        ],
        fraud_category=FraudCategory.PAYMENT_SCAM,
        message="URGENT! Send money now.",
    )

    assert len(intelligence.evidence) == 3

    assert any(
        "Urgency" in evidence
        for evidence in intelligence.evidence
    )

    assert any(
        "money" in evidence.lower()
        or "payment" in evidence.lower()
        for evidence in intelligence.evidence
    )

    assert any(
        "suspicious" in evidence.lower()
        for evidence in intelligence.evidence
    )
