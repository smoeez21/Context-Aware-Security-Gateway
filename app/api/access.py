
import json

from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from sqlalchemy.orm import Session

from app.database.database import get_db

from app.database.models import (
    AccessRequest,
    Resource,
    RiskAssessment,
    Approval,
)

from app.database.execution_models import (
    RequestPayload,
)

from app.schemas.request import (
    AccessRequestCreate,
    AccessRequestResponse,
)

from app.security.authentication import (
    authenticate_agent,
)

from app.security.authorization import (
    authorize_request,
)

from app.security.sensitivity import (
    analyze_resource_sensitivity,
)

from app.security.context_analyzer import (
    analyze_context,
)

from app.security.risk_engine import (
    calculate_risk,
)

from app.security.decision_engine import (
    make_security_decision,
)

from app.services.resource_executor import (
    execute_resource,
)

from app.services.audit_service import (
    save_audit_log,
)


router = APIRouter(
    prefix="/access-request",
    tags=["Security Gateway"],
)


@router.post(
    "",
    response_model=AccessRequestResponse,
)
def process_access_request(
    payload: AccessRequestCreate,
    db: Session = Depends(get_db),
):

    # ========================================================
    # 1. Request Identity
    # ========================================================

    request_code = "REQ-" + uuid4().hex.upper()

    action = payload.action.value
    destination = payload.destination.value

    # Validate required operation payload.
    if action in {"WRITE", "UPDATE"}:
        if payload.payload_data is None:
            raise HTTPException(
                status_code=422,
                detail=(
                    "WRITE and UPDATE require payload_data."
                ),
            )

    # ========================================================
    # 2. Resource Lookup
    # ========================================================

    resource = (
        db.query(Resource)
        .filter(
            Resource.resource_code
            == payload.resource_code
        )
        .first()
    )

    # Unknown resource attempts must also be logged.
    if resource is None:

        request = AccessRequest(
            request_code=request_code,
            agent_id=None,
            resource_id=None,
            presented_agent_code=payload.agent_code,
            action=action,
            destination=destination,
            authentication_status="NOT_CHECKED",
            authorization_status="DENIED",
            decision="BLOCK",
            status="COMPLETED",
        )

        try:
            db.add(request)
            db.flush()

            db.add(
                RiskAssessment(
                    request_id=request.id,
                    risk_score=80,
                    risk_level="CRITICAL",
                    permission_violation=True,
                    sensitive_resource=False,
                    external_destination=(
                        destination == "EXTERNAL"
                    ),
                    reasons=json.dumps([
                        {
                            "factor": "Unknown resource",
                            "points": 80,
                        }
                    ]),
                )
            )

            save_audit_log(
                db=db,
                access_request=request,
                resource_name=payload.resource_code,
                risk_score=80,
                risk_level="CRITICAL",
                decision="BLOCK",
                reason="Unknown resource identifier.",
                final_outcome="ACCESS_DENIED",
            )

            db.commit()
            db.refresh(request)

        except Exception:
            db.rollback()
            raise

        return AccessRequestResponse(
            request_code=request_code,
            agent_code=payload.agent_code,
            resource_code=payload.resource_code,
            action=action,
            destination=destination,
            authentication_status="NOT_CHECKED",
            authorization_status="DENIED",
            resource_sensitivity=None,
            context=None,
            risk_score=80,
            risk_level="CRITICAL",
            risk_factors=[
                {
                    "factor": "Unknown resource",
                    "points": 80,
                }
            ],
            decision="BLOCK",
            reason="Unknown resource identifier.",
            status="COMPLETED",
            timestamp=request.requested_at,
        )

    # ========================================================
    # 3. Sensitivity
    # ========================================================

    sensitivity = analyze_resource_sensitivity(
        resource
    )

    # ========================================================
    # 4. Authentication
    # ========================================================

    auth = authenticate_agent(
        db=db,
        agent_code=payload.agent_code,
        credential=payload.credential,
    )

    agent = auth["agent"]
    authenticated = auth["authenticated"]

    authorized = False
    authorization_reason = None
    context = None

    authentication_status = (
        "SUCCESS" if authenticated else "FAILED"
    )

    authorization_status = "NOT_CHECKED"

    # ========================================================
    # 5. Authorization and Context
    # ========================================================

    if authenticated:

        authz = authorize_request(
            db=db,
            agent_id=agent.id,
            resource_id=resource.id,
            action=action,
            destination=destination,
        )

        authorized = authz["authorized"]
        authorization_reason = authz["reason"]

        authorization_status = (
            "ALLOWED" if authorized else "DENIED"
        )

        if authorized:

            context = analyze_context(
                db=db,
                agent_id=agent.id,
                resource_id=resource.id,
                action=action,
                destination=destination,
            )

            context["sensitive_external_send"] = (
                action == "SEND"
                and destination == "EXTERNAL"
                and sensitivity["sensitivity"]
                in {"HIGH", "CRITICAL"}
            )

    # ========================================================
    # 6. Risk
    # ========================================================

    risk = calculate_risk(
        authenticated=authenticated,
        authorized=authorized,
        sensitivity_result=sensitivity,
        context_result=context,
    )

    # ========================================================
    # 7. Decision
    # ========================================================

    result = make_security_decision(
        authenticated=authenticated,
        authorized=authorized,
        risk_score=risk["risk_score"],
    )

    decision = result["decision"]
    reason = result["reason"]

    if not authenticated:
        reason = auth["reason"]

    elif not authorized:
        reason = authorization_reason

    # ========================================================
    # 8. Initial Request Status
    # ========================================================

    if decision == "ALLOW":
        status = "AUTHORIZED_NOT_EXECUTED"

    elif decision == "HUMAN_APPROVAL":
        status = "PENDING_APPROVAL"

    else:
        status = "COMPLETED"

    # ========================================================
    # 9. Create Request
    # ========================================================

    request = AccessRequest(
        request_code=request_code,
        agent_id=agent.id if agent else None,
        resource_id=resource.id,
        presented_agent_code=payload.agent_code,
        action=action,
        destination=destination,
        authentication_status=authentication_status,
        authorization_status=authorization_status,
        decision=decision,
        status=status,
    )

    try:

        db.add(request)
        db.flush()

        # ====================================================
        # 10. Save Risk Assessment
        # ====================================================

        assessment = RiskAssessment(
            request_id=request.id,
            risk_score=risk["risk_score"],
            risk_level=risk["risk_level"],
            permission_violation=(
                authenticated and not authorized
            ),
            sensitive_resource=(
                sensitivity["is_sensitive"]
            ),
            external_destination=(
                destination == "EXTERNAL"
            ),
            unusual_activity=(
                context.get("unusual_activity", False)
                if context else False
            ),
            high_frequency=(
                context.get("high_frequency", False)
                if context else False
            ),
            suspicious_sequence=(
                context.get("suspicious_sequence", False)
                if context else False
            ),
            reasons=json.dumps(
                risk["risk_factors"]
            ),
        )

        db.add(assessment)

        # ====================================================
        # 11. Preserve Original Payload
        # ====================================================

        if payload.payload_data is not None:

            db.add(
                RequestPayload(
                    request_id=request.id,
                    payload_json=json.dumps(
                        payload.payload_data
                    ),
                )
            )

        # ====================================================
        # 12. Enforce Decision
        # ====================================================

        if decision == "ALLOW":

            try:

                execute_resource(
                    db=db,
                    access_request=request,
                    resource=resource,
                    payload_data=payload.payload_data,
                )

                request.status = "EXECUTED"
                final_outcome = "EXECUTED"

            except ValueError as exc:

                request.status = "EXECUTION_FAILED"
                final_outcome = "EXECUTION_FAILED"
                reason = str(exc)

        elif decision == "HUMAN_APPROVAL":

            approval = Approval(
                request_id=request.id,
                status="PENDING",
            )

            db.add(approval)

            final_outcome = "PENDING_APPROVAL"

        else:

            final_outcome = "ACCESS_DENIED"

        # ====================================================
        # 13. Audit Logging
        # ====================================================

        save_audit_log(
            db=db,
            access_request=request,
            resource_name=resource.name,
            risk_score=risk["risk_score"],
            risk_level=risk["risk_level"],
            decision=decision,
            reason=reason,
            final_outcome=final_outcome,
        )

        # ====================================================
        # 14. Commit Everything
        # ====================================================

        db.commit()
        db.refresh(request)

    except Exception:

        db.rollback()
        raise

    # ========================================================
    # 15. Return Response
    # ========================================================

    return AccessRequestResponse(
        request_code=request_code,
        agent_code=payload.agent_code,
        resource_code=payload.resource_code,
        action=action,
        destination=destination,
        authentication_status=authentication_status,
        authorization_status=authorization_status,
        resource_sensitivity=sensitivity["sensitivity"],
        context=context,
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        risk_factors=risk["risk_factors"],
        decision=decision,
        reason=reason,
        status=request.status,
        timestamp=request.requested_at,
    )
