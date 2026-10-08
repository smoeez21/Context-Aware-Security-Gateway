
import json

import httpx

from agents.client import GatewayClient

from agents.simulator import (
    SALES_AGENT,
    HR_AGENT,
    FINANCE_AGENT,
    RESEARCH_AGENT,
)

from agents.scenarios import (
    SCENARIOS,
    run_scenario,
)


def make_client(captured_requests):

    def handler(request):

        if request.url.path == "/health":

            return httpx.Response(
                200,
                json={"status": "healthy"},
            )

        if request.url.path == "/access-request":

            body = json.loads(
                request.content
            )

            captured_requests.append(body)

            # Minimal mocked gateway response.
            return httpx.Response(
                200,
                json={
                    "request_code": "REQ-TEST",
                    "decision": "ALLOW",
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "status": "EXECUTED",
                    "context": {},
                },
            )

        return httpx.Response(
            404,
            json={"detail": "Not found"},
        )

    transport = httpx.MockTransport(
        handler
    )

    return GatewayClient(
        base_url="http://testserver",
        transport=transport,
    )


def test_four_agents_exist():

    agents = [
        SALES_AGENT,
        HR_AGENT,
        FINANCE_AGENT,
        RESEARCH_AGENT,
    ]

    assert len(agents) == 4

    departments = {
        agent.department
        for agent in agents
    }

    assert departments == {
        "Sales",
        "HR",
        "Finance",
        "Research",
    }


def test_all_twelve_scenarios_registered():

    assert sorted(SCENARIOS.keys()) == list(
        range(1, 13)
    )


def test_sales_agent_sends_correct_request():

    captured = []

    with make_client(captured) as client:

        SALES_AGENT.request_access(
            client,
            resource_code="RES-SALES",
            action="READ",
        )

    assert len(captured) == 1

    assert captured[0]["agent_code"] == (
        "AGENT-SALES-001"
    )

    assert captured[0]["resource_code"] == (
        "RES-SALES"
    )

    assert captured[0]["action"] == "READ"


def test_repeated_requests_scenario():

    captured = []

    with make_client(captured) as client:

        result = run_scenario(
            7,
            client,
        )

    assert len(result.responses) == 10

    assert len(captured) == 10

    assert all(
        req["resource_code"] == "RES-SALES"
        for req in captured
    )


def test_suspicious_sequence_scenario():

    captured = []

    with make_client(captured) as client:

        result = run_scenario(
            8,
            client,
        )

    assert len(result.responses) == 3

    sequence = [
        req["resource_code"]
        for req in captured
    ]

    assert sequence == [
        "RES-CUSTOMERS",
        "RES-CREDENTIALS",
        "RES-CUSTOMERS",
    ]

    assert captured[-1]["action"] == "SEND"

    assert captured[-1]["destination"] == (
        "EXTERNAL"
    )


def test_invalid_agent_scenario():

    captured = []

    with make_client(captured) as client:

        run_scenario(
            9,
            client,
        )

    assert captured[0]["agent_code"] == (
        "AGENT-UNKNOWN-999"
    )


def test_credentials_not_in_export():

    captured = []

    with make_client(captured) as client:

        result = run_scenario(
            1,
            client,
        )

    exported = json.dumps(
        result.to_dict()
    )

    assert "sales-demo-key" not in exported

    assert "credential" not in exported
