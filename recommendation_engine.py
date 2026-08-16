RECOMMENDATIONS = {
    "urgency": {
        "explanation": "The message attempts to pressure you into acting quickly.",
        "recommendation": "Pause and verify the request before taking any action.",
        "priority_action": "Do not act solely because the message creates urgency."
    },

    "credential_request": {
        "explanation": "The message requests sensitive authentication information.",
        "recommendation": "Never share OTPs, passwords, PINs, seed phrases, recovery phrases, or private keys.",
        "priority_action": "Do not disclose authentication credentials."
    },

    "payment_request": {
        "explanation": "The message requests money, a transfer, or a payment.",
        "recommendation": "Independently verify the payment request using a trusted communication channel.",
        "priority_action": "Do not send money until the request has been verified."
    },

    "threat_language": {
        "explanation": "The message uses threats involving account suspension, blocking, legal action, or similar consequences.",
        "recommendation": "Verify the claimed account problem through the organization's official website or known contact information.",
        "priority_action": "Do not respond to threats by following instructions in the message."
    },

    "social_engineering": {
        "explanation": "The message contains language commonly associated with impersonation or social-engineering attempts.",
        "recommendation": "Independently verify the identity of the person or organization contacting you.",
        "priority_action": "Do not trust the sender's identity without independent verification."
    }
}


def generate_recommendations(findings):

    recommendations = []
    priority_actions = []
    explanations = []

    for finding in findings:

        category = finding["category"]

        guidance = RECOMMENDATIONS.get(category)

        if not guidance:
            continue

        if guidance["explanation"] not in explanations:
            explanations.append(guidance["explanation"])

        if guidance["recommendation"] not in recommendations:
            recommendations.append(guidance["recommendation"])

        if guidance["priority_action"] not in priority_actions:
            priority_actions.append(guidance["priority_action"])

    return {
        "explanations": explanations,
        "recommendations": recommendations,
        "priority_actions": priority_actions
    }
