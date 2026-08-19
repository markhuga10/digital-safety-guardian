from dataclasses import dataclass
from enum import Enum
from typing import List

from checkam_ng.fraud_taxonomy import FraudCategory


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CommunicationChannel(str, Enum):
    SMS = "SMS"
    WHATSAPP = "WHATSAPP"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SOCIAL_MEDIA = "SOCIAL_MEDIA"
    WEBSITE = "WEBSITE"
    OTHER = "OTHER"


@dataclass
class ThreatIntelligence:
    """Structured intelligence about a suspected fraud attempt."""

    impersonated_entity: str
    fraud_type: FraudCategory
    target: str
    communication_channel: CommunicationChannel
    requested_action: str
    likely_impact: str
    confidence: ConfidenceLevel
    evidence: List[str]

    def __post_init__(self):
        required_fields = {
            "impersonated_entity": self.impersonated_entity,
            "target": self.target,
            "requested_action": self.requested_action,
            "likely_impact": self.likely_impact,
        }

        for field_name, value in required_fields.items():
            if not isinstance(value, str):
                raise TypeError(
                    f"{field_name} must be a string"
                )

            if not value.strip():
                raise ValueError(
                    f"{field_name} cannot be empty"
                )

        if not isinstance(self.fraud_type, FraudCategory):
            raise TypeError(
                "fraud_type must be a FraudCategory"
            )

        if not isinstance(
            self.communication_channel,
            CommunicationChannel,
        ):
            raise TypeError(
                "communication_channel must be a CommunicationChannel"
            )

        if not isinstance(
            self.confidence,
            ConfidenceLevel,
        ):
            raise TypeError(
                "confidence must be a ConfidenceLevel"
            )

        if not isinstance(self.evidence, list):
            raise TypeError(
                "evidence must be a list"
            )

        if not all(
            isinstance(item, str)
            for item in self.evidence
        ):
            raise TypeError(
                "every evidence item must be a string"
            )
