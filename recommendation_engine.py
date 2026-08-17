RECOMMENDATION_LIBRARY = {

    "urgency": {
        "explanation": (
            "The message attempts to pressure you into acting quickly."
        ),
        "recommendation": (
            "Pause and verify the request before taking any action."
        ),
        "priority_action": (
            "Do not act solely because the message creates urgency."
        ),
    },

    "credential_request": {
        "explanation": (
            "The message requests sensitive authentication information."
        ),
        "recommendation": (
            "Never share OTPs, passwords, PINs, seed phrases, "
            "recovery phrases, or private keys."
        ),
        "priority_action": (
            "Do not disclose authentication credentials."
        ),
    },

    "payment_request": {
        "explanation": (
            "The message requests money, a transfer, or a payment."
        ),
        "recommendation": (
            "Independently verify the payment request using a trusted "
            "communication channel."
        ),
        "priority_action": (
            "Do not send money until the request has been verified."
        ),
    },

    "threat_language": {
        "explanation": (
            "The message uses threats involving account suspension, "
            "blocking, legal action, or similar consequences."
        ),
        "recommendation": (
            "Verify the claimed account problem through the organization's "
            "official website or known contact information."
        ),
        "priority_action": (
            "Do not respond to threats by following instructions in the message."
        ),
    },

    "social_engineering": {
        "explanation": (
            "The message may be attempting to impersonate a trusted "
            "person, organization, or support service."
        ),
        "recommendation": (
            "Verify the sender independently using a trusted communication "
            "channel."
        ),
        "priority_action": (
            "Do not trust the identity claimed in the message without verification."
        ),
    },
}


def generate_recommendations(findings):

    explanations = []
    recommendations = []
    priority_actions = []

    processed_categories = set()

    for finding in findings:

        category = finding.get("category")

        if category in processed_categories:
            continue

        processed_categories.add(category)

        guidance = RECOMMENDATION_LIBRARY.get(category)

        if not guidance:
            continue

        explanations.append(guidance["explanation"])
        recommendations.append(guidance["recommendation"])
        priority_actions.append(guidance["priority_action"])

    return {
        "explanations": explanations,
        "recommendations": recommendations,
        "priority_actions": priority_actions,
    }
