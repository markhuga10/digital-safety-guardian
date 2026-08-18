import argparse
import json

from detector import analyze_message
from risk_engine import calculate_risk
from recommendation_engine import generate_recommendations
from url_detector import analyze_url
from url_risk_engine import calculate_url_risk
from combined_risk_engine import calculate_overall_risk
from attack_pattern_engine import classify_attack_patterns

from models import AnalysisResult


def analyze(message, url=None):
    """
    Analyze a message and optional URL.

    Returns:
        dict: Complete Digital Safety Guardian analysis result.
    """

    # ---------------------------------------------------------
    # Message analysis
    # ---------------------------------------------------------

    message_findings = analyze_message(message)

    message_risk = calculate_risk(
        message_findings
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
    # URL analysis
    # ---------------------------------------------------------

    url_findings = []

    url_risk = {
        "score": 0,
        "level": "MINIMAL"
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
        url_risk
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
        recommendations=recommendations,
    )

    # ---------------------------------------------------------
    # Return dictionary for backwards compatibility
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
        )
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a message and optional URL"
    )

    analyze_parser.add_argument(
        "message",
        help="Message to analyze"
    )

    analyze_parser.add_argument(
        "--url",
        help="Optional URL to analyze"
    )

    analyze_parser.add_argument(
        "--json",
        action="store_true",
        help="Output analysis as JSON"
    )

    args = parser.parse_args()

    if args.command == "analyze":

        result = analyze(
            args.message,
            args.url
        )

        if args.json:

            print(
                json.dumps(
                    result,
                    indent=2
                )
            )

        else:

            print_report(result)

    else:

        parser.print_help()


if __name__ == "__main__":
    main()
