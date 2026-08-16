from urllib.parse import urlparse
import ipaddress
import re

from trusted_domains import TRUSTED_DOMAINS


def is_lookalike_domain(hostname: str):

    hostname = hostname.lower().strip(".")

    for trusted_domain in TRUSTED_DOMAINS:

        if hostname == trusted_domain:
            continue

        # Check for one-character substitution
        if len(hostname) == len(trusted_domain):

            differences = sum(
                1
                for a, b in zip(hostname, trusted_domain)
                if a != b
            )

            if differences == 1:
                return trusted_domain

        # Check for one-character insertion/removal
        if abs(len(hostname) - len(trusted_domain)) == 1:

            shorter = (
                hostname
                if len(hostname) < len(trusted_domain)
                else trusted_domain
            )

            longer = (
                trusted_domain
                if len(hostname) < len(trusted_domain)
                else hostname
            )

            for i in range(len(longer)):

                candidate = longer[:i] + longer[i + 1:]

                if candidate == shorter:
                    return trusted_domain

    return None


def analyze_url(url: str):

    findings = []

    parsed = urlparse(url)

    # Check whether a scheme exists
    if parsed.scheme not in ["http", "https"]:

        findings.append({
            "category": "invalid_scheme",
            "description": "The URL does not use HTTP or HTTPS."
        })

    # Check for plain HTTP
    if parsed.scheme == "http":

        findings.append({
            "category": "insecure_protocol",
            "description": "The URL uses HTTP instead of HTTPS."
        })

    hostname = parsed.hostname

    if not hostname:

        findings.append({
            "category": "invalid_url",
            "description": "The URL does not contain a valid hostname."
        })

        return findings

    # Check for lookalike domains
    lookalike = is_lookalike_domain(hostname)

    if lookalike:

        findings.append({
            "category": "lookalike_domain",
            "reference_domain": lookalike,
            "description": (
                f"The hostname appears similar to the trusted domain "
                f"'{lookalike}'."
            )
        })

    # Check whether hostname is an IP address
    try:

        ipaddress.ip_address(hostname)

        findings.append({
            "category": "ip_address_host",
            "description": "The URL uses an IP address instead of a domain name."
        })

    except ValueError:
        pass

    # Check for excessive subdomains
    labels = hostname.split(".")

    if len(labels) >= 5:

        findings.append({
            "category": "excessive_subdomains",
            "description": (
                "The domain contains an unusually large number "
                "of subdomains."
            )
        })

    # Suspicious URL keywords
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "wallet",
        "recover",
        "recovery",
        "confirm",
    ]

    for keyword in suspicious_keywords:

        if re.search(
            rf"\b{re.escape(keyword)}\b",
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

    # Check for username/password-style URL structure
    if parsed.username:

        findings.append({
            "category": "embedded_credentials",
            "description": (
                "The URL contains user-information before the hostname."
            )
        })

    return findings
