
import json

from datetime import datetime, timezone

from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database.models import (
    Approval,
    AccessRequest,
    Agent,
    Resource,
    RiskAssessment,
)

from app.database.execution_models import (
    RequestPayload,
)

from app.security.authorization import (
    authorize_request,
)

from app.services.resource_executor import (
    execute_resource,
)

from app.services.audit_service import (
    save_audit_log,
)


def review_approval(
    db: Session,
    approval_id: int,
    reviewer: str,
    approve: bool,
    comment: str | None = None,
):

    # --------------------------------------------------------
    # Find pending approval
    # --------------------------------------------------------

    approval = (
        db.query(Approval)
        .filter(
            Approval.id == approval_id
        )
        .first()
    )

    if approval is None:
        raise HTTPException(
            status_code=404,
            detail="Approval not found",
        )

    if approval.status != "PENDING":
        raise HTTPException(
            status_code=409,
            detail="Request has already been reviewed",
        )

    request = (
        db.query(AccessRequest)
        .filter(
            AccessRequest.id == approval.request_id
        )
        .first()
    )

    if (
        request is None
        or request.decision != "HUMAN_APPROVAL"
        or request.status != "PENDING_APPROVAL"
    ):
        raise HTTPException(
            status_code=409,
            detail="Request is not eligible for approval",
        )

    risk = (
        db.query(RiskAssessment)
        .filter(
            RiskAssessment.request_id == request.id
        )
        .first()
    )

    resource = db.get(
        Resource,
        request.resource_id,
    )

    agent = db.get(
        Agent,
        request.agent_id,
    )

    resource_name = (
        resource.name if resource
        else "Unknown resource"
    )

    def finalize(
        approval_status,
        outcome,
        reason,
    ):

        approval.status = approval_status
        approval.reviewed_by = reviewer
        approval.admin_comment = comment
        approval.reviewed_at = (
            datetime.now(timezone.utc)
        )

        request.status = outcome

        save_audit_log(
            db=db,
            access_request=request,
            resource_name=resource_name,
            risk_score=risk.risk_score,
            risk_level=risk.risk_level,
            decision="HUMAN_APPROVAL",
            reason=reason,
            final_outcome=outcome,
        )

        db.commit()

        return {
            "approval_id": approval.id,
            "request_code": request.request_code,
            "approval_status": approval.status,
            "final_outcome": outcome,
            "reason": reason,
        }

    # --------------------------------------------------------
    # Administrator rejects
    # --------------------------------------------------------

    if not approve:

        return finalize(
            approval_status="REJECTED",
            outcome="REJECTED",
            reason="Administrator rejected request.",
        )

    # --------------------------------------------------------
    # Revalidate security conditions before approval
    # --------------------------------------------------------

    if (
        agent is None
        or resource is None
        or agent.status != "ACTIVE"
    ):

        return finalize(
            approval_status="REJECTED",
            outcome="ACCESS_DENIED",
            reason=(
                "Request is no longer eligible: "
                "agent or resource unavailable."
            ),
        )

    authorization = authorize_request(
        db=db,
        agent_id=agent.id,
        resource_id=resource.id,
        action=request.action,
        destination=request.destination,
    )

    if not authorization["authorized"]:

        return finalize(
            approval_status="REJECTED",
            outcome="ACCESS_DENIED",
            reason=(
                "Current authorization policy "
                "does not permit execution."
            ),
        )

    # --------------------------------------------------------
    # Retrieve preserved operation payload
    # --------------------------------------------------------

    saved_payload = (
        db.query(RequestPayload)
        .filter(
            RequestPayload.request_id == request.id
        )
        .first()
    )

    payload_data = (
        json.loads(saved_payload.payload_json)
        if saved_payload
        else None
    )

    # --------------------------------------------------------
    # Execute approved operation
    # --------------------------------------------------------

    try:

        execute_resource(
            db=db,
            access_request=request,
            resource=resource,
            payload_data=payload_data,
        )

        return finalize(
            approval_status="APPROVED",
            outcome="EXECUTED",
            reason=(
                "Administrator approved request "
                "and resource operation executed."
            ),
        )

    except ValueError as exc:

        return finalize(
            approval_status="REJECTED",
            outcome="EXECUTION_FAILED",
            reason=str(exc),
        )
