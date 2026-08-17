import re
from urllib.parse import urlparse
from ipaddress import ip_address

from trusted_domains import TRUSTED_DOMAINS


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "signin",
    "wallet",
    "recover",
    "recovery",
    "support",
]


def levenshtein_distance(a, b):
    """Calculate the edit distance between two strings."""

    if len(a) < len(b):
        return levenshtein_distance(b, a)

    previous_row = list(range(len(b) + 1))

    for i, char_a in enumerate(a, start=1):

        current_row = [i]

        for j, char_b in enumerate(b, start=1):

            insertions = current_row[j - 1] + 1
            deletions = previous_row[j] + 1
            substitutions = previous_row[j - 1] + (char_a != char_b)

            current_row.append(
                min(
                    insertions,
                    deletions,
                    substitutions
                )
            )

        previous_row = current_row

    return previous_row[-1]


def is_ip_address(hostname):
    """Return True if hostname is a valid IP address."""

    try:
        ip_address(hostname)
        return True

    except ValueError:
        return False


def is_lookalike_domain(hostname):
    """Detect domains that closely resemble trusted domains."""

    if not hostname:
        return None

    hostname = hostname.lower().strip(".")

    for trusted_domain in TRUSTED_DOMAINS:

        trusted_domain = trusted_domain.lower()

        if hostname == trusted_domain:
            continue

        hostname_name = hostname.split(".")[0]
        trusted_name = trusted_domain.split(".")[0]

        distance = levenshtein_distance(
            hostname_name,
            trusted_name
        )

        if distance <= 1:
            return trusted_domain

    return None


def analyze_url(url):
    """Analyze a URL for common phishing indicators."""

    findings = []

    try:
        parsed = urlparse(url)

    except Exception:
        return [
            {
                "category": "invalid_url",
                "description": "The URL could not be parsed."
            }
        ]

    # Validate scheme
    if parsed.scheme.lower() not in ["http", "https"]:

        findings.append({
            "category": "invalid_scheme",
            "description": "The URL does not use HTTP or HTTPS."
        })

    # HTTP is not encrypted
    if parsed.scheme.lower() == "http":

        findings.append({
            "category": "insecure_protocol",
            "description": "The URL uses HTTP instead of HTTPS."
        })

    # Validate hostname
    hostname = parsed.hostname

    if not hostname:

        findings.append({
            "category": "invalid_url",
            "description": "The URL does not contain a valid hostname."
        })

        return findings

    hostname = hostname.lower().strip(".")

    # Detect IP address hosts
    if is_ip_address(hostname):

        findings.append({
            "category": "ip_address_host",
            "description": (
                "The URL uses an IP address instead of a domain name."
            )
        })

    # Detect embedded credentials
    if parsed.username or parsed.password:

        findings.append({
            "category": "embedded_credentials",
            "description": (
                "The URL contains embedded username or password information."
            )
        })

    # Detect excessive subdomains
    hostname_parts = hostname.split(".")

    if len(hostname_parts) >= 5:

        findings.append({
            "category": "excessive_subdomains",
            "description": (
                "The hostname contains an unusually large number "
                "of subdomains."
            )
        })

    # Detect suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:

        if re.search(
            r"\b" + re.escape(keyword) + r"\b",
            url,
            re.IGNORECASE
        ):

            findings.append({
                "category": "suspicious_keyword",
                "keyword": keyword,
                "description": (
                    f"The URL contains the security-sensitive "
                    f"keyword '{keyword}'."
                )
            })

            break

    # Detect lookalike domains
    lookalike = is_lookalike_domain(hostname)

    if lookalike:

        findings.append({
            "category": "lookalike_domain",
            "reference_domain": lookalike,
            "description": (
                f"The hostname appears similar to the trusted "
                f"domain '{lookalike}'."
            )
        })

    return findings
