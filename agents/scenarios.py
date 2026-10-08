
from dataclasses import dataclass
from typing import Callable

from agents.client import GatewayClient

from agents.simulator import (
    SALES_AGENT,
    HR_AGENT,
    FINANCE_AGENT,
    RESEARCH_AGENT,
)


@dataclass
class ScenarioResult:

    number: int
    name: str
    responses: list[dict]

    expected_decision: str | None = None
    note: str = ""

    @property
    def final_response(self) -> dict:
        return self.responses[-1]

    def to_dict(self) -> dict:
        return {
            "scenario": self.number,
            "name": self.name,
            "expected_decision": self.expected_decision,
            "actual_decision": self.final_response.get(
                "decision"
            ),
            "risk_score": self.final_response.get(
                "risk_score"
            ),
            "risk_level": self.final_response.get(
                "risk_level"
            ),
            "final_status": self.final_response.get(
                "status"
            ),
            "request_codes": [
                r.get("request_code")
                for r in self.responses
            ],
            "note": self.note,
        }


# ============================================================
# SCENARIO 1
# Authorized Sales Data Access
# ============================================================

def scenario_1(client):

    response = SALES_AGENT.request_access(
        client,
        resource_code="RES-SALES",
        action="READ",
    )

    return ScenarioResult(
        1,
        "Authorized Sales Data Access",
        [response],
        expected_decision="ALLOW",
    )


# ============================================================
# SCENARIO 2
# Unauthorized Salary Access
# ============================================================

def scenario_2(client):

    response = SALES_AGENT.request_access(
        client,
        resource_code="RES-SALARY",
        action="READ",
    )

    return ScenarioResult(
        2,
        "Unauthorized Salary Access",
        [response],
        expected_decision="BLOCK",
    )


# ============================================================
# SCENARIO 3
# Unauthorized Financial Access
# ============================================================

def scenario_3(client):

    response = RESEARCH_AGENT.request_access(
        client,
        resource_code="RES-FINANCE",
        action="DELETE",
    )

    return ScenarioResult(
        3,
        "Unauthorized Financial Access",
        [response],
        expected_decision="BLOCK",
    )


# ============================================================
# SCENARIO 4
# Credential Access Attempt
# ============================================================

def scenario_4(client):

    response = SALES_AGENT.request_access(
        client,
        resource_code="RES-CREDENTIALS",
        action="READ",
    )

    return ScenarioResult(
        4,
        "Credential Access Attempt",
        [response],
        expected_decision="BLOCK",
    )


# ============================================================
# SCENARIO 5
# Sensitive Customer Data Access
# ============================================================

def scenario_5(client):

    response = SALES_AGENT.request_access(
        client,
        resource_code="RES-CUSTOMERS",
        action="READ",
    )

    return ScenarioResult(
        5,
        "Sensitive Customer Data Access",
        [response],
        note=(
            "Authorized HIGH-sensitivity access. "
            "Final decision also depends on context."
        ),
    )


# ============================================================
# SCENARIO 6
# External Customer Data Transfer
# ============================================================

def scenario_6(client):

    response = SALES_AGENT.request_access(
        client,
        resource_code="RES-CUSTOMERS",
        action="SEND",
        destination="EXTERNAL",
    )

    return ScenarioResult(
        6,
        "External Customer Data Transfer",
        [response],
        note=(
            "Normally HIGH risk and HUMAN_APPROVAL. "
            "May become BLOCK if recent activity "
            "raises the score to CRITICAL."
        ),
    )


# ============================================================
# SCENARIO 7
# Repeated Requests
# ============================================================

def scenario_7(client):

    responses = []

    for _ in range(10):

        response = SALES_AGENT.request_access(
            client,
            resource_code="RES-SALES",
            action="READ",
        )

        responses.append(response)

    return ScenarioResult(
        7,
        "Repeated Requests",
        responses,
        note=(
            "Send 10 consecutive requests. "
            "The final context should flag "
            "high_frequency if they occur "
            "within one minute."
        ),
    )


# ============================================================
# SCENARIO 8
# Suspicious Resource Sequence
# ============================================================

def scenario_8(client):

    responses = []

    # First: customer-data access.
    responses.append(
        SALES_AGENT.request_access(
            client,
            resource_code="RES-CUSTOMERS",
            action="READ",
        )
    )

    # Second: unauthorized credential access.
    responses.append(
        SALES_AGENT.request_access(
            client,
            resource_code="RES-CREDENTIALS",
            action="READ",
        )
    )

    # Third: attempt external data transfer.
    responses.append(
        SALES_AGENT.request_access(
            client,
            resource_code="RES-CUSTOMERS",
            action="SEND",
            destination="EXTERNAL",
        )
    )

    return ScenarioResult(
        8,
        "Suspicious Resource Sequence",
        responses,
        note=(
            "Customer Data -> Credentials -> "
            "External SEND. Expected sequence "
            "indicator if all requests are "
            "inside the analysis window."
        ),
    )


# ============================================================
# SCENARIO 9
# Invalid Agent
# ============================================================

def scenario_9(client):

    response = client.access_request(
        agent_code="AGENT-UNKNOWN-999",
        credential="invalid-demo-key",
        resource_code="RES-SALES",
        action="READ",
    )

    return ScenarioResult(
        9,
        "Invalid Agent",
        [response],
        expected_decision="BLOCK",
    )


# ============================================================
# SCENARIO 10
# Invalid Authentication
# ============================================================

def scenario_10(client):

    response = client.access_request(
        agent_code=SALES_AGENT.agent_code,
        credential="wrong-demo-key",
        resource_code="RES-SALES",
        action="READ",
    )

    return ScenarioResult(
        10,
        "Invalid Authentication",
        [response],
        expected_decision="BLOCK",
    )


# ============================================================
# SCENARIO 11
# High-Sensitivity Authorized Access
# ============================================================

def scenario_11(client):

    response = HR_AGENT.request_access(
        client,
        resource_code="RES-SALARY",
        action="READ",
    )

    return ScenarioResult(
        11,
        "High-Sensitivity Authorized Access",
        [response],
        note=(
            "HR has permission to access salary data. "
            "Risk is calculated from CRITICAL sensitivity "
            "and recent context."
        ),
    )


# ============================================================
# SCENARIO 12
# Human Approval Request
# ============================================================

def scenario_12(client):

    response = SALES_AGENT.request_access(
        client,
        resource_code="RES-CUSTOMERS",
        action="SEND",
        destination="EXTERNAL",
    )

    return ScenarioResult(
        12,
        "Human Approval Request",
        [response],
        note=(
            "An authorized high-risk transfer normally "
            "creates a pending administrator approval. "
            "Existing history may escalate it to BLOCK."
        ),
    )


# ============================================================
# SCENARIO REGISTRY
# ============================================================

SCENARIOS: dict[int, Callable] = {
    1: scenario_1,
    2: scenario_2,
    3: scenario_3,
    4: scenario_4,
    5: scenario_5,
    6: scenario_6,
    7: scenario_7,
    8: scenario_8,
    9: scenario_9,
    10: scenario_10,
    11: scenario_11,
    12: scenario_12,
}


def run_scenario(
    number: int,
    client: GatewayClient,
) -> ScenarioResult:

    scenario = SCENARIOS.get(number)

    if scenario is None:
        raise ValueError(
            f"Unknown scenario number: {number}"
        )

    return scenario(client)
