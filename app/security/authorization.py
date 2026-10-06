from sqlalchemy.orm import Session

from app.database.models import Policy


def authorize_request(
    db: Session,
    agent_id: int,
    resource_id: int,
    action: str,
    destination: str
):

    policy = (
        db.query(Policy)
        .filter(
            Policy.agent_id == agent_id,
            Policy.resource_id == resource_id,
            Policy.action == action,
            Policy.destination == destination
        )
        .first()
    )

    # Default-deny security model
    if not policy:
        return {
            "authorized": False,
            "effect": "DENY",
            "policy": None,
            "reason": (
                "No matching access policy exists. "
                "Default deny applied."
            )
        }

    if policy.effect == "DENY":
        return {
            "authorized": False,
            "effect": "DENY",
            "policy": policy,
            "reason": (
                policy.description
                or "Policy explicitly denies access"
            )
        }

    return {
        "authorized": True,
        "effect": "ALLOW",
        "policy": policy,
        "reason": (
            policy.description
            or "Policy permits access"
        )
    }