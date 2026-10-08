
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


router = APIRouter(
    prefix="/access-request",
    tags=["Security Gateway"],
)


# ============================================================
# PROCESS ACCESS REQUEST
# ============================================================

@router.post(
    "",
    response_model=AccessRequestResponse,
)
def process_access_request(
    payload: AccessRequestCreate,
    db: Session = Depends(get_db),
):

    # --------------------------------------------------------
    # 1. Generate Request ID
    # --------------------------------------------------------

    request_code = (
        "REQ-" + uuid4().hex.upper()
    )

    action = payload.action.value
    destination = payload.destination.value

    # --------------------------------------------------------
    # 2. Identify Requested Resource
    # --------------------------------------------------------

    resource = (
        db.query(Resource)
        .filter(
            Resource.resource_code
            == payload.resource_code
        )
        .first()
    )

    if resource is None:
        raise HTTPException(
            status_code=404,
            detail="Requested resource does not exist",
        )

    # --------------------------------------------------------
    # 3. Resource Sensitivity Analysis
    # --------------------------------------------------------

    sensitivity_result = (
        analyze_resource_sensitivity(resource)
    )

    # --------------------------------------------------------
    # 4. Agent Authentication
    # --------------------------------------------------------

    auth_result = authenticate_agent(
        db=db,
        agent_code=payload.agent_code,
        credential=payload.credential,
    )

    agent = auth_result["agent"]

    authenticated = auth_result["authenticated"]

    # --------------------------------------------------------
    # 5. Set Default Security States
    # --------------------------------------------------------

    authorized = False

    authentication_status = (
        "SUCCESS" if authenticated else "FAILED"
    )

    authorization_status = "NOT_CHECKED"

    authorization_reason = None

    context_result = None

    # --------------------------------------------------------
    # 6. Authorization
    # --------------------------------------------------------

    if authenticated:

        authorization_result = authorize_request(
            db=db,
            agent_id=agent.id,
            resource_id=resource.id,
            action=action,
            destination=destination,
        )

        authorized = authorization_result["authorized"]

        authorization_reason = authorization_result["reason"]

        authorization_status = (
            "ALLOWED" if authorized else "DENIED"
        )

        # ----------------------------------------------------
        # 7. Context Analysis
        # ----------------------------------------------------

        if authorized:

            context_result = analyze_context(
                db=db,
                agent_id=agent.id,
                resource_id=resource.id,
                action=action,
                destination=destination,
            )

            # Additional derived risk indicator.
            # This is included only in risk calculation,
            # not in the existing context response schema.

            context_result["sensitive_external_send"] = (
                action == "SEND"
                and destination == "EXTERNAL"
                and sensitivity_result["sensitivity"]
                in {"HIGH", "CRITICAL"}
            )

    # --------------------------------------------------------
    # 8. Calculate Risk
    # --------------------------------------------------------

    risk_result = calculate_risk(
        authenticated=authenticated,
        authorized=authorized,
        sensitivity_result=sensitivity_result,
        context_result=context_result,
    )

    risk_score = risk_result["risk_score"]
    risk_level = risk_result["risk_level"]

    # --------------------------------------------------------
    # 9. Make Final Security Decision
    # --------------------------------------------------------

    decision_result = make_security_decision(
        authenticated=authenticated,
        authorized=authorized,
        risk_score=risk_score,
    )

    decision = decision_result["decision"]
    decision_reason = decision_result["reason"]

    # Preserve the specific failure explanation.
    if not authenticated:
        decision_reason = auth_result["reason"]

    elif not authorized:
        decision_reason = authorization_reason

    # --------------------------------------------------------
    # 10. Determine Request Status
    # --------------------------------------------------------
    #
    # Phase 6 does NOT actually execute protected resources.
    #
    # ALLOW means authorization and risk checks passed,
    # but resource execution is still pending implementation.
    #
    # HUMAN_APPROVAL does not execute the request.
    # The approval queue will be implemented in Phase 7.
    # --------------------------------------------------------

    if decision == "ALLOW":
        request_status = "AUTHORIZED_NOT_EXECUTED"

    elif decision == "HUMAN_APPROVAL":
        request_status = "PENDING_APPROVAL"

    else:
        request_status = "COMPLETED"

    # --------------------------------------------------------
    # 11. Create Access Request Database Record
    # --------------------------------------------------------

    access_request = AccessRequest(
        request_code=request_code,

        agent_id=agent.id if agent else None,

        resource_id=resource.id,

        presented_agent_code=payload.agent_code,

        action=action,
        destination=destination,

        authentication_status=authentication_status,
        authorization_status=authorization_status,

        decision=decision,
        status=request_status,
    )

    # --------------------------------------------------------
    # 12. Save Request and Risk Assessment Together
    # --------------------------------------------------------

    try:

        db.add(access_request)

        # Generates database ID before creating
        # the linked risk assessment.

        db.flush()

        risk_assessment = RiskAssessment(
            request_id=access_request.id,

            risk_score=risk_score,
            risk_level=risk_level,

            permission_violation=(
                authenticated and not authorized
            ),

            sensitive_resource=(
                sensitivity_result["is_sensitive"]
            ),

            external_destination=(
                destination == "EXTERNAL"
            ),

            unusual_activity=(
                context_result.get("unusual_activity", False)
                if context_result
                else False
            ),

            high_frequency=(
                context_result.get("high_frequency", False)
                if context_result
                else False
            ),

            suspicious_sequence=(
                context_result.get("suspicious_sequence", False)
                if context_result
                else False
            ),

            reasons=json.dumps(
                risk_result["risk_factors"]
            ),
        )

        db.add(risk_assessment)

        # Single transaction:
        # both records succeed or both fail.

        db.commit()

        db.refresh(access_request)

    except Exception:
        db.rollback()
        raise

    # --------------------------------------------------------
    # 13. Return Complete Gateway Response
    # --------------------------------------------------------

    return AccessRequestResponse(
        request_code=request_code,

        agent_code=payload.agent_code,
        resource_code=payload.resource_code,

        action=action,
        destination=destination,

        authentication_status=authentication_status,
        authorization_status=authorization_status,

        resource_sensitivity=(
            sensitivity_result["sensitivity"]
        ),

        context=context_result,

        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors=risk_result["risk_factors"],

        decision=decision,
        reason=decision_reason,

        status=request_status,

        timestamp=access_request.requested_at,
    )
