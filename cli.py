import argparse
import json

from detector import analyze_message
from risk_engine import calculate_risk
from recommendation_engine import generate_recommendations
from url_detector import analyze_url
from url_risk_engine import calculate_url_risk
from combined_risk_engine import calculate_overall_risk
from attack_pattern_engine import classify_attack_patterns

from checkam_ng.fraud_classifier import classify_fraud
from checkam_ng.threat_intelligence_engine import (
    generate_threat_intelligence,
)

from models import AnalysisResult


def analyze(message, url=None):
    """
    Analyze a message and optional URL.

    Returns:
        dict: Complete CheckAm-NG analysis result.
    """

    # ---------------------------------------------------------
    # Message analysis
    # ---------------------------------------------------------

    message_findings = analyze_message(message)

    message_risk = calculate_risk(
        message_findings
    )

    # ---------------------------------------------------------
    # URL analysis
    # ---------------------------------------------------------

    url_findings = []

    url_risk = {
        "score": 0,
        "level": "MINIMAL",
    }

    if url:

        url_findings = analyze_url(
            url
        )

        url_risk = calculate_url_risk(
            url_findings
        )

    # ---------------------------------------------------------
    # Combined risk
    # ---------------------------------------------------------

    overall_risk = calculate_overall_risk(
        message_risk,
        url_risk,
    )

    # ---------------------------------------------------------
    # Recommendations
    # ---------------------------------------------------------

    recommendations = generate_recommendations(
        message_findings
    )

    # ---------------------------------------------------------
    # Attack-pattern classification
    # ---------------------------------------------------------

    attack_pattern_result = classify_attack_patterns(
        message_findings
    )

    attack_patterns = attack_pattern_result.get(
        "patterns",
        []
    )

    # ---------------------------------------------------------
    # Fraud classification
    # ---------------------------------------------------------

    fraud_category = classify_fraud(
        message_findings=message_findings,
        url_findings=url_findings,
        message=message,
    )

    # ---------------------------------------------------------
    # Convert FraudCategory enum to string
    # ---------------------------------------------------------

    fraud_category_value = (
        fraud_category.value
        if hasattr(fraud_category, "value")
        else str(fraud_category)
    )

    # ---------------------------------------------------------
    # Threat intelligence
    # ---------------------------------------------------------

    threat_intelligence = generate_threat_intelligence(
        message_findings=message_findings,
        url_findings=url_findings,
        fraud_category=fraud_category,
        message=message,
    )

    # ---------------------------------------------------------
    # Validate complete result with Pydantic
    # ---------------------------------------------------------

    validated_result = AnalysisResult(
        message_findings=message_findings,
        message_risk=message_risk,
        url_findings=url_findings,
        url_risk=url_risk,
        overall_risk=overall_risk,
        attack_patterns=attack_patterns,
        fraud_category=fraud_category_value,
        threat_intelligence=threat_intelligence,
        recommendations=recommendations,
    )

    # ---------------------------------------------------------
    # Return dictionary
    # ---------------------------------------------------------

    return validated_result.model_dump()


def print_report(result):

    print()
    print("=" * 60)
    print("             DIGITAL SAFETY GUARDIAN")
    print("=" * 60)

    # ---------------------------------------------------------
    # Message risk
    # ---------------------------------------------------------

    print()
    print("MESSAGE RISK")
    print("-" * 60)

    print(
        f"Score: {result['message_risk']['score']}/100"
    )

    print(
        f"Level: {result['message_risk']['level']}"
    )

    if result["message_findings"]:

        print("\nIndicators:")

        for finding in result["message_findings"]:

            print(
                f"  [!] {finding['category']}"
            )

    else:

        print("Indicators: None detected")

    # ---------------------------------------------------------
    # URL risk
    # ---------------------------------------------------------

    print()
    print("URL RISK")
    print("-" * 60)

    print(
        f"Score: {result['url_risk']['score']}/100"
    )

    print(
        f"Level: {result['url_risk']['level']}"
    )

    if result["url_findings"]:

        print("\nIndicators:")

        for finding in result["url_findings"]:

            print(
                f"  [!] {finding['category']}"
            )

    else:

        print("Indicators: None detected")

    # ---------------------------------------------------------
    # Overall risk
    # ---------------------------------------------------------

    print()
    print("OVERALL RISK")
    print("-" * 60)

    print(
        f"Score: {result['overall_risk']['score']}/100"
    )

    print(
        f"Level: {result['overall_risk']['level']}"
    )

    # ---------------------------------------------------------
    # Fraud classification
    # ---------------------------------------------------------

    print()
    print("FRAUD CLASSIFICATION")
    print("-" * 60)

    print(
        f"Category: {result['fraud_category']}"
    )

    # ---------------------------------------------------------
    # Threat intelligence
    # ---------------------------------------------------------

    intelligence = result.get(
        "threat_intelligence"
    )

    if intelligence:

        print()
        print("THREAT INTELLIGENCE")
        print("-" * 60)

        print(
            f"Impersonated Entity: "
            f"{intelligence['impersonated_entity']}"
        )

        print(
            f"Fraud Type: "
            f"{intelligence['fraud_type']}"
        )

        print(
            f"Target: "
            f"{intelligence['target']}"
        )

        print(
            f"Communication Channel: "
            f"{intelligence['communication_channel']}"
        )

        print(
            f"Requested Action: "
            f"{intelligence['requested_action']}"
        )

        print(
            f"Likely Impact: "
            f"{intelligence['likely_impact']}"
        )

        print(
            f"Confidence: "
            f"{intelligence['confidence']}"
        )

        if intelligence["evidence"]:

            print()
            print("Evidence:")

            for evidence in intelligence["evidence"]:

                print(
                    f"  [!] {evidence}"
                )

    # ---------------------------------------------------------
    # Attack patterns
    # ---------------------------------------------------------

    print()
    print("ATTACK PATTERNS")
    print("-" * 60)

    if result["attack_patterns"]:

        for pattern in result["attack_patterns"]:

            print(
                f"  [!] {pattern}"
            )

    else:

        print("None detected")

    # ---------------------------------------------------------
    # Recommendations
    # ---------------------------------------------------------

    recommendations = result["recommendations"]

    if recommendations["explanations"]:

        print()
        print("EXPLANATIONS")
        print("-" * 60)

        for explanation in recommendations["explanations"]:

            print(
                f"  • {explanation}"
            )

    if recommendations["recommendations"]:

        print()
        print("RECOMMENDATIONS")
        print("-" * 60)

        for recommendation in recommendations["recommendations"]:

            print(
                f"  • {recommendation}"
            )

    if recommendations["priority_actions"]:

        print()
        print("PRIORITY ACTIONS")
        print("-" * 60)

        for action in recommendations["priority_actions"]:

            print(
                f"  [!] {action}"
            )

    print()
    print("=" * 60)


def main():

    parser = argparse.ArgumentParser(
        prog="dsg",
        description=(
            "Digital Safety Guardian - "
            "message and URL security analysis"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a message and optional URL",
    )

    analyze_parser.add_argument(
        "message",
        help="Message to analyze",
    )

    analyze_parser.add_argument(
        "--url",
        help="Optional URL to analyze",
    )

    analyze_parser.add_argument(
        "--json",
        action="store_true",
        help="Output analysis as JSON",
    )

    args = parser.parse_args()

    if args.command == "analyze":

        result = analyze(
            args.message,
            args.url,
        )

        if args.json:

            print(
                json.dumps(
                    result,
                    indent=2,
                )
            )

        else:

            print_report(result)

    else:

        parser.print_help()


if __name__ == "__main__":
    main()
