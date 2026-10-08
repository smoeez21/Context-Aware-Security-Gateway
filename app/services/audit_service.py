
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.database.models import AuditLog


def utc_now():
    return datetime.now(timezone.utc)


def save_audit_log(
    db: Session,
    access_request,
    resource_name: str,
    risk_score: int,
    risk_level: str,
    decision: str,
    reason: str,
    final_outcome: str,
):
    """
    Create or update the audit record for a request.

    No commit is performed here. The caller owns
    the database transaction.
    """

    log = (
        db.query(AuditLog)
        .filter(
            AuditLog.request_id
            == access_request.id
        )
        .first()
    )

    if log is None:

        log = AuditLog(
            request_id=access_request.id,
            agent_code=(
                access_request.presented_agent_code
            ),
            action=access_request.action,
            resource_name=resource_name,
            destination=access_request.destination,
            risk_score=risk_score,
            risk_level=risk_level,
            decision=decision,
            reason=reason,
            final_outcome=final_outcome,
        )

        db.add(log)

    else:

        log.decision = decision
        log.reason = reason
        log.final_outcome = final_outcome
        log.updated_at = utc_now()

    return log
