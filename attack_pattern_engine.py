ATTACK_PATTERNS = {
    "credential_phishing": {
        "required": {
            "urgency",
            "credential_request",
            "social_engineering",
        }
    },

    "payment_scam": {
        "required": {
            "urgency",
            "payment_request",
        }
    },

    "account_takeover": {
        "required": {
            "threat_language",
            "credential_request",
        }
    },

    "impersonation": {
        "required": {
            "social_engineering",
            "credential_request",
        }
    },
}


def classify_attack_patterns(findings):
    """
    Classify possible attack patterns from detected message indicators.

    The function correlates existing detector findings rather than
    analyzing raw message text itself.
    """

    categories = {
        finding.get("category")
        for finding in findings
        if finding.get("category")
    }

    detected_patterns = []

    for pattern_name, pattern_definition in ATTACK_PATTERNS.items():

        required_categories = pattern_definition["required"]

        if required_categories.issubset(categories):
            detected_patterns.append(pattern_name)

    return {
        "patterns": detected_patterns
    }
