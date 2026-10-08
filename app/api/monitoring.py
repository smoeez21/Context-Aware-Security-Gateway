
from collections import Counter

from fastapi import (
    APIRouter,
    Depends,
    Query,
)

from sqlalchemy.orm import Session

from app.database.database import get_db

from app.database.models import (
    Agent,
    Resource,
    AccessRequest,
    RiskAssessment,
    Approval,
)

from app.security.admin_auth import (
    require_admin,
)


router = APIRouter(
    prefix="/monitoring",
    tags=["Monitoring"],
    dependencies=[Depends(require_admin)],
)


@router.get("/dashboard")
def get_dashboard_data(
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
):

    # ========================================================
    # 1. OVERALL STATISTICS
    # ========================================================

    total_requests = db.query(AccessRequest).count()

    allowed_requests = (
        db.query(AccessRequest)
        .filter(AccessRequest.decision == "ALLOW")
        .count()
    )

    blocked_requests = (
        db.query(AccessRequest)
        .filter(AccessRequest.decision == "BLOCK")
        .count()
    )

    approval_requests = (
        db.query(AccessRequest)
        .filter(
            AccessRequest.decision == "HUMAN_APPROVAL"
        )
        .count()
    )

    pending_approvals = (
        db.query(Approval)
        .filter(Approval.status == "PENDING")
        .count()
    )

    high_risk_requests = (
        db.query(RiskAssessment)
        .filter(
            RiskAssessment.risk_level.in_(
                ["HIGH", "CRITICAL"]
            )
        )
        .count()
    )

    # ========================================================
    # 2. RISK DISTRIBUTION
    # ========================================================

    risk_distribution = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    assessments = (
        db.query(RiskAssessment.risk_level)
        .all()
    )

    for (level,) in assessments:

        if level in risk_distribution:
            risk_distribution[level] += 1

    # ========================================================
    # 3. RECENT REQUESTS
    # ========================================================

    recent = (
        db.query(AccessRequest)
        .order_by(
            AccessRequest.requested_at.desc(),
            AccessRequest.id.desc(),
        )
        .limit(limit)
        .all()
    )

    recent_requests = []

    for request in recent:

        risk = request.risk_assessment

        resource_name = (
            request.resource.name
            if request.resource
            else "Unknown Resource"
        )

        recent_requests.append({
            "id": request.id,
            "request_code": request.request_code,
            "agent_code": (
                request.presented_agent_code
            ),
            "resource": resource_name,
            "action": request.action,
            "destination": request.destination,
            "risk_score": (
                risk.risk_score if risk else None
            ),
            "risk_level": (
                risk.risk_level if risk else None
            ),
            "decision": request.decision,
            "status": request.status,
            "timestamp": request.requested_at,
        })

    # ========================================================
    # 4. AGENT ACTIVITY
    # ========================================================

    agents = db.query(Agent).all()

    agent_activity = []

    for agent in agents:

        agent_requests = (
            db.query(AccessRequest)
            .filter(
                AccessRequest.agent_id == agent.id
            )
        )

        agent_activity.append({
            "agent_code": agent.agent_code,
            "name": agent.name,
            "department": agent.department,
            "status": agent.status,
            "total_requests": agent_requests.count(),
            "blocked_requests": (
                agent_requests.filter(
                    AccessRequest.decision == "BLOCK"
                ).count()
            ),
        })

    # ========================================================
    # 5. RESOURCE ACTIVITY
    # ========================================================

    resources = db.query(Resource).all()

    resource_activity = []

    for resource in resources:

        resource_requests = (
            db.query(AccessRequest)
            .filter(
                AccessRequest.resource_id
                == resource.id
            )
        )

        resource_activity.append({
            "resource_code": resource.resource_code,
            "name": resource.name,
            "sensitivity": resource.sensitivity,
            "resource_type": resource.resource_type,
            "total_requests": resource_requests.count(),
            "blocked_requests": (
                resource_requests.filter(
                    AccessRequest.decision == "BLOCK"
                ).count()
            ),
        })

    # ========================================================
    # 6. DECISION DISTRIBUTION
    # ========================================================

    decision_distribution = {
        "ALLOW": allowed_requests,
        "BLOCK": blocked_requests,
        "HUMAN_APPROVAL": approval_requests,
    }

    # ========================================================
    # 7. RESPONSE
    # ========================================================

    return {
        "overview": {
            "total_requests": total_requests,
            "allowed_requests": allowed_requests,
            "blocked_requests": blocked_requests,
            "approval_requests": approval_requests,
            "pending_approvals": pending_approvals,
            "high_risk_requests": high_risk_requests,
            "total_agents": len(agents),
            "total_resources": len(resources),
        },
        "decision_distribution": decision_distribution,
        "risk_distribution": risk_distribution,
        "agent_activity": agent_activity,
        "resource_activity": resource_activity,
        "recent_requests": recent_requests,
    }
