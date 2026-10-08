
import json

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from sqlalchemy.orm import Session

from app.database.database import get_db

from app.database.models import (
    AuditLog,
    AccessRequest,
    RiskAssessment,
    Approval,
)

from app.database.execution_models import (
    ResourceExecution,
)

from app.security.admin_auth import (
    require_admin,
)


router = APIRouter(
    tags=["Audit Logs"],
    dependencies=[
        Depends(require_admin)
    ],
)


@router.get("/audit-logs")
def get_audit_logs(
    db: Session = Depends(get_db),
):

    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.id.desc())
        .limit(200)
        .all()
    )

    return [
        {
            "id": log.id,
            "request_id": log.request_id,
            "agent_code": log.agent_code,
            "resource": log.resource_name,
            "action": log.action,
            "destination": log.destination,
            "risk_score": log.risk_score,
            "risk_level": log.risk_level,
            "decision": log.decision,
            "reason": log.reason,
            "final_outcome": log.final_outcome,
            "timestamp": log.created_at,
        }
        for log in logs
    ]


@router.get("/requests/{request_id}")
def get_request_details(
    request_id: int,
    db: Session = Depends(get_db),
):

    request = db.get(
        AccessRequest,
        request_id,
    )

    if request is None:
        raise HTTPException(
            status_code=404,
            detail="Request not found",
        )

    risk = (
        db.query(RiskAssessment)
        .filter(
            RiskAssessment.request_id == request.id
        )
        .first()
    )

    approval = (
        db.query(Approval)
        .filter(
            Approval.request_id == request.id
        )
        .first()
    )

    audit = (
        db.query(AuditLog)
        .filter(
            AuditLog.request_id == request.id
        )
        .first()
    )

    execution = (
        db.query(ResourceExecution)
        .filter(
            ResourceExecution.request_id == request.id
        )
        .first()
    )

    return {
        "request_code": request.request_code,
        "agent_code": request.presented_agent_code,
        "action": request.action,
        "destination": request.destination,
        "decision": request.decision,
        "status": request.status,
        "risk": (
            {
                "score": risk.risk_score,
                "level": risk.risk_level,
                "factors": json.loads(
                    risk.reasons or "[]"
                ),
            }
            if risk else None
        ),
        "approval": (
            {
                "status": approval.status,
                "reviewed_by": approval.reviewed_by,
                "comment": approval.admin_comment,
            }
            if approval else None
        ),
        "execution": (
            json.loads(execution.result_json)
            if execution else None
        ),
        "audit": (
            {
                "decision": audit.decision,
                "reason": audit.reason,
                "final_outcome": audit.final_outcome,
            }
            if audit else None
        ),
    }
