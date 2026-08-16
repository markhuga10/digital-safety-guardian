import re


THREAT_PATTERNS = {
    "urgency": [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bnow\b",
        r"\btoday\b",
        r"\bwithin\s+\d+\s+(minutes?|hours?)\b",
    ],

    "credential_request": [
        r"\botp\b",
        r"\bverification code\b",
        r"\bpassword\b",
        r"\bpasscode\b",
        r"\bpin\b",
        r"\bseed phrase\b",
        r"\brecovery phrase\b",
        r"\bprivate key\b",
    ],

    "payment_request": [
        r"\bsend money\b",
        r"\btransfer\b",
        r"\bpay\b",
        r"\bprocessing fee\b",
        r"\bdeposit\b",
    ],

    "threat_language": [
        r"\baccount.*suspend",
        r"\baccount.*blocked",
        r"\baccount.*closed",
        r"\blegal action\b",
        r"\barrest\b",
    ],

    "social_engineering": [
        r"\bverify your account\b",
        r"\bconfirm your identity\b",
        r"\bsecurity team\b",
        r"\bcustomer support\b",
        r"\badmin\b",
    ],
}


def analyze_message(message: str):

    findings = []

    for category, patterns in THREAT_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, message, re.IGNORECASE):

                findings.append({
                    "category": category,
                    "pattern": pattern
                })

                break

    return findings
