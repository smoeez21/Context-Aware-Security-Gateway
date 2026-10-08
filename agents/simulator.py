
from dataclasses import dataclass, field

from agents.client import GatewayClient


@dataclass
class SimulatedAgent:

    agent_code: str
    name: str
    department: str

    # Do not expose credentials in repr output.
    credential: str = field(repr=False)

    def request_access(
        self,
        client: GatewayClient,
        resource_code: str,
        action: str,
        destination: str = "INTERNAL",
        payload_data: dict | None = None,
    ):

        return client.access_request(
            agent_code=self.agent_code,
            credential=self.credential,
            resource_code=resource_code,
            action=action,
            destination=destination,
            payload_data=payload_data,
        )


# ============================================================
# SIMULATED ORGANIZATIONAL AGENTS
# ============================================================

SALES_AGENT = SimulatedAgent(
    agent_code="AGENT-SALES-001",
    name="Sales Agent",
    department="Sales",
    credential="sales-demo-key",
)

HR_AGENT = SimulatedAgent(
    agent_code="AGENT-HR-001",
    name="HR Agent",
    department="HR",
    credential="hr-demo-key",
)

FINANCE_AGENT = SimulatedAgent(
    agent_code="AGENT-FIN-001",
    name="Finance Agent",
    department="Finance",
    credential="finance-demo-key",
)

RESEARCH_AGENT = SimulatedAgent(
    agent_code="AGENT-RES-001",
    name="Research Agent",
    department="Research",
    credential="research-demo-key",
)


AGENTS = {
    "sales": SALES_AGENT,
    "hr": HR_AGENT,
    "finance": FINANCE_AGENT,
    "research": RESEARCH_AGENT,
}
