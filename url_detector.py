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
    "support",
]


def levenshtein_distance(a, b):

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

    try:
        ip_address(hostname)
        return True

    except ValueError:
        return False


def is_lookalike_domain(hostname):

    if not hostname:
        return None

    hostname = hostname.lower()

    for trusted_domain in TRUSTED_DOMAINS:

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

    if not parsed.scheme or not parsed.netloc:

        return [
            {
                "category": "invalid_url",
                "description": (
                    "The URL is missing a valid scheme or hostname."
                )
            }
        ]

    hostname = parsed.hostname

    if not hostname:

        return [
            {
                "category": "invalid_url",
                "description": (
                    "The URL does not contain a valid hostname."
                )
            }
        ]

    # Check protocol
    if parsed.scheme.lower() == "http":

        findings.append({
            "category": "insecure_protocol",
            "description": (
                "The URL uses HTTP instead of HTTPS."
            )
        })

    # Check whether hostname is an IP address
    if is_ip_address(hostname):

        findings.append({
            "category": "ip_address_host",
            "description": (
                "The URL uses an IP address instead of a domain name."
            )
        })

    # Check for embedded credentials
    if parsed.username or parsed.password:

        findings.append({
            "category": "embedded_credentials",
            "description": (
                "The URL contains embedded username or password information."
            )
        })

    # Check suspicious keywords
    url_text = url.lower()

    for keyword in SUSPICIOUS_KEYWORDS:

        if re.search(
            r"\b" + re.escape(keyword) + r"\b",
            url_text
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

    # Check excessive subdomains
    hostname_parts = hostname.split(".")

    if len(hostname_parts) >= 5:

        findings.append({
            "category": "excessive_subdomains",
            "description": (
                "The hostname contains an unusually large number "
                "of subdomains."
            )
        })

    # Check lookalike domain
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
