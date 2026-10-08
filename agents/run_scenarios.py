
import argparse
import json

from datetime import datetime, timezone
from pathlib import Path

import httpx

from agents.client import GatewayClient
from agents.scenarios import (
    SCENARIOS,
    run_scenario,
)


RESULTS_DIRECTORY = Path("results")

RESULTS_FILE = (
    RESULTS_DIRECTORY / "phase8_results.json"
)


def print_result(result):

    response = result.final_response

    print()
    print("=" * 60)

    print(
        f"SCENARIO {result.number}: {result.name}"
    )

    print("-" * 60)

    print(
        "Decision:",
        response.get("decision"),
    )

    print(
        "Risk Score:",
        response.get("risk_score"),
    )

    print(
        "Risk Level:",
        response.get("risk_level"),
    )

    print(
        "Status:",
        response.get("status"),
    )

    print(
        "Number of Requests:",
        len(result.responses),
    )

    context = response.get("context")

    if context:

        print(
            "High Frequency:",
            context.get("high_frequency"),
        )

        print(
            "Suspicious Sequence:",
            context.get("suspicious_sequence"),
        )

        print(
            "Unusual Activity:",
            context.get("unusual_activity"),
        )

    if result.expected_decision:

        matches = (
            response.get("decision")
            == result.expected_decision
        )

        print(
            "Policy Expectation:",
            "MATCH" if matches else "MISMATCH",
        )

    if result.note:
        print("Note:", result.note)


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Context-Aware Security Gateway "
            "Agent Scenario Simulator"
        ),
    )

    parser.add_argument(
        "--scenario",
        type=int,
        choices=list(SCENARIOS.keys()),
        help="Run one scenario (1-12).",
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all 12 scenarios.",
    )

    args = parser.parse_args()

    if args.all:
        selected = sorted(SCENARIOS)

    elif args.scenario is not None:
        selected = [args.scenario]

    else:
        parser.error(
            "Specify --all or --scenario NUMBER"
        )

    results = []

    try:

        with GatewayClient() as client:

            print("Checking gateway connection...")

            health = client.health_check()

            print(
                "Gateway status:",
                health.get("status"),
            )

            for number in selected:

                result = run_scenario(
                    number,
                    client,
                )

                results.append(result)

                print_result(result)

    except httpx.HTTPError as exc:

        print()
        print("Gateway communication failed.")
        print("Error:", exc)

        print(
            "Ensure FastAPI is running at "
            "http://127.0.0.1:8000"
        )

        raise SystemExit(1)

    # --------------------------------------------------------
    # Export results
    # --------------------------------------------------------

    RESULTS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    output = {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "total_scenarios": len(results),

        "results": [
            result.to_dict()
            for result in results
        ],
    }

    RESULTS_FILE.write_text(
        json.dumps(
            output,
            indent=4,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 60)

    print(
        "Results saved to:",
        RESULTS_FILE,
    )

    print(
        "Scenarios executed:",
        len(results),
    )

    print("=" * 60)


if __name__ == "__main__":
    main()
