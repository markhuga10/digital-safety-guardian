import pytest

from checkam_ng.fraud_taxonomy import FraudCategory

from checkam_ng.threat_intelligence import (
    CommunicationChannel,
    ConfidenceLevel,
    ThreatIntelligence,
)


def test_threat_intelligence_accepts_complete_data():
    intelligence = ThreatIntelligence(
        impersonated_entity="Bank",
        fraud_type=FraudCategory.CREDENTIAL_PHISHING,
        target="banking_credentials",
        communication_channel=CommunicationChannel.SMS,
        requested_action="Click a link and verify the account",
        likely_impact="Account compromise and financial loss",
        confidence=ConfidenceLevel.HIGH,
        evidence=[
            "Urgent account suspension warning",
            "Credential verification request",
            "Suspicious link",
        ],
    )

    assert intelligence.impersonated_entity == "Bank"

    assert (
        intelligence.fraud_type
        == FraudCategory.CREDENTIAL_PHISHING
    )

    assert intelligence.target == "banking_credentials"

    assert (
        intelligence.communication_channel
        == CommunicationChannel.SMS
    )

    assert intelligence.requested_action == (
        "Click a link and verify the account"
    )

    assert intelligence.likely_impact == (
        "Account compromise and financial loss"
    )

    assert intelligence.confidence == ConfidenceLevel.HIGH

    assert len(intelligence.evidence) == 3


def test_invalid_confidence_is_rejected():
    with pytest.raises(TypeError):
        ThreatIntelligence(
            impersonated_entity="Bank",
            fraud_type=FraudCategory.CREDENTIAL_PHISHING,
            target="banking_credentials",
            communication_channel=CommunicationChannel.SMS,
            requested_action="Click the link",
            likely_impact="Account compromise",
            confidence="very_high",
            evidence=["Urgency"],
        )


def test_invalid_channel_is_rejected():
    with pytest.raises(TypeError):
        ThreatIntelligence(
            impersonated_entity="Bank",
            fraud_type=FraudCategory.CREDENTIAL_PHISHING,
            target="banking_credentials",
            communication_channel="UnknownChannel",
            requested_action="Click the link",
            likely_impact="Account compromise",
            confidence=ConfidenceLevel.HIGH,
            evidence=["Suspicious link"],
        )


def test_invalid_fraud_category_is_rejected():
    with pytest.raises(TypeError):
        ThreatIntelligence(
            impersonated_entity="Bank",
            fraud_type="unknown_scam",
            target="banking_credentials",
            communication_channel=CommunicationChannel.SMS,
            requested_action="Click the link",
            likely_impact="Account compromise",
            confidence=ConfidenceLevel.HIGH,
            evidence=["Suspicious link"],
        )


def test_empty_required_field_is_rejected():
    with pytest.raises(ValueError):
        ThreatIntelligence(
            impersonated_entity="",
            fraud_type=FraudCategory.CREDENTIAL_PHISHING,
            target="banking_credentials",
            communication_channel=CommunicationChannel.SMS,
            requested_action="Click the link",
            likely_impact="Account compromise",
            confidence=ConfidenceLevel.HIGH,
            evidence=["Urgency"],
        )


def test_evidence_must_be_a_list():
    with pytest.raises(TypeError):
        ThreatIntelligence(
            impersonated_entity="Bank",
            fraud_type=FraudCategory.CREDENTIAL_PHISHING,
            target="banking_credentials",
            communication_channel=CommunicationChannel.SMS,
            requested_action="Click the link",
            likely_impact="Account compromise",
            confidence=ConfidenceLevel.HIGH,
            evidence="Suspicious link",
        )


def test_evidence_items_must_be_strings():
    with pytest.raises(TypeError):
        ThreatIntelligence(
            impersonated_entity="Bank",
            fraud_type=FraudCategory.CREDENTIAL_PHISHING,
            target="banking_credentials",
            communication_channel=CommunicationChannel.SMS,
            requested_action="Click the link",
            likely_impact="Account compromise",
            confidence=ConfidenceLevel.HIGH,
            evidence=["Urgency", 123],
        )
