
from fastapi import (
    APIRouter,
    Depends,
)

from pydantic import BaseModel

from sqlalchemy.orm import Session

from app.database.database import get_db

from app.database.models import (
    Approval,
    AccessRequest,
    RiskAssessment,
)

from app.security.admin_auth import (
    require_admin,
)

from app.services.approval_service import (
    review_approval,
)


router = APIRouter(
    prefix="/approvals",
    tags=["Human Approval"],
    dependencies=[
        Depends(require_admin)
    ],
)


class ApprovalReview(BaseModel):
    comment: str | None = None


@router.get("")
def get_approvals(
    db: Session = Depends(get_db),
):

    approvals = (
        db.query(Approval)
        .order_by(Approval.id.desc())
        .all()
    )

    results = []

    for approval in approvals:

        request = db.get(
            AccessRequest,
            approval.request_id,
        )

        risk = (
            db.query(RiskAssessment)
            .filter(
                RiskAssessment.request_id
                == approval.request_id
            )
            .first()
        )

        results.append({
            "approval_id": approval.id,
            "request_code": request.request_code,
            "agent_code": (
                request.presented_agent_code
            ),
            "resource_id": request.resource_id,
            "action": request.action,
            "destination": request.destination,
            "risk_score": risk.risk_score,
            "risk_level": risk.risk_level,
            "status": approval.status,
            "reviewed_by": approval.reviewed_by,
            "admin_comment": approval.admin_comment,
        })

    return results


@router.post("/{approval_id}/approve")
def approve_request(
    approval_id: int,
    payload: ApprovalReview,
    db: Session = Depends(get_db),
):

    return review_approval(
        db=db,
        approval_id=approval_id,
        reviewer="ADMIN",
        approve=True,
        comment=payload.comment,
    )


@router.post("/{approval_id}/reject")
def reject_request(
    approval_id: int,
    payload: ApprovalReview,
    db: Session = Depends(get_db),
):

    return review_approval(
        db=db,
        approval_id=approval_id,
        reviewer="ADMIN",
        approve=False,
        comment=payload.comment,
    )
