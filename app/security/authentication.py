from sqlalchemy.orm import Session

from app.database.models import Agent
from app.security.credentials import hash_credential


def authenticate_agent(
    db: Session,
    agent_code: str,
    credential: str
):

    agent = (
        db.query(Agent)
        .filter(
            Agent.agent_code == agent_code
        )
        .first()
    )

    # Agent does not exist
    if not agent:
        return {
            "authenticated": False,
            "agent": None,
            "reason": "Agent does not exist"
        }

    # Agent exists but is disabled
    if agent.status != "ACTIVE":
        return {
            "authenticated": False,
            "agent": agent,
            "reason": "Agent is not active"
        }

    supplied_hash = hash_credential(
        credential
    )

    # Credential does not match
    if supplied_hash != agent.credential_hash:
        return {
            "authenticated": False,
            "agent": agent,
            "reason": "Invalid authentication credential"
        }

    return {
        "authenticated": True,
        "agent": agent,
        "reason": "Authentication successful"
    }