from datetime import datetime, timezone
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


router = APIRouter(
    prefix="/access-request",
    tags=["Security Gateway"]
)


@router.post(
    "",
    response_model=AccessRequestResponse
)
def process_access_request(
    payload: AccessRequestCreate,
    db: Session = Depends(get_db)
):

    # -------------------------------------------------
    # Generate unique request ID
    # -------------------------------------------------

    request_code = (
        "REQ-"
        + uuid4().hex[:12].upper()
    )

    action = payload.action.value
    destination = payload.destination.value

    # -------------------------------------------------
    # Find requested resource
    # -------------------------------------------------

    resource = (
        db.query(Resource)
        .filter(
            Resource.resource_code
            == payload.resource_code
        )
        .first()
    )

    if not resource:
        raise HTTPException(
            status_code=404,
            detail="Requested resource does not exist"
        )

    # -------------------------------------------------
    # Authentication
    # -------------------------------------------------

    auth_result = authenticate_agent(
        db=db,
        agent_code=payload.agent_code,
        credential=payload.credential
    )

    agent = auth_result["agent"]

    # -------------------------------------------------
    # Authentication FAILED
    # -------------------------------------------------

    if not auth_result["authenticated"]:

        access_request = AccessRequest(
            request_code=request_code,

            agent_id=(
                agent.id
                if agent
                else None
            ),

            resource_id=resource.id,

            presented_agent_code=payload.agent_code,

            action=action,
            destination=destination,

            authentication_status="FAILED",
            authorization_status="NOT_CHECKED",

            decision="BLOCK",
            status="COMPLETED"
        )

        db.add(access_request)
        db.commit()

        return AccessRequestResponse(
            request_code=request_code,
            agent_code=payload.agent_code,
            resource_code=payload.resource_code,

            action=action,
            destination=destination,

            authentication_status="FAILED",
            authorization_status="NOT_CHECKED",

            decision="BLOCK",

            reason=auth_result["reason"],

            timestamp=datetime.now(
                timezone.utc
            )
        )

    # -------------------------------------------------
    # Authentication SUCCESSFUL
    # -------------------------------------------------

    authorization_result = authorize_request(
        db=db,
        agent_id=agent.id,
        resource_id=resource.id,
        action=action,
        destination=destination
    )

    # -------------------------------------------------
    # Authorization FAILED
    # -------------------------------------------------

    if not authorization_result["authorized"]:

        access_request = AccessRequest(
            request_code=request_code,
            agent_id=agent.id,
            resource_id=resource.id,

            presented_agent_code=payload.agent_code,

            action=action,
            destination=destination,

            authentication_status="SUCCESS",
            authorization_status="DENIED",

            decision="BLOCK",
            status="COMPLETED"
        )

        db.add(access_request)
        db.commit()

        return AccessRequestResponse(
            request_code=request_code,

            agent_code=payload.agent_code,
            resource_code=payload.resource_code,

            action=action,
            destination=destination,

            authentication_status="SUCCESS",
            authorization_status="DENIED",

            decision="BLOCK",

            reason=authorization_result["reason"],

            timestamp=datetime.now(
                timezone.utc
            )
        )

    # -------------------------------------------------
    # Authentication + Authorization SUCCESSFUL
    # -------------------------------------------------

    access_request = AccessRequest(
        request_code=request_code,

        agent_id=agent.id,
        resource_id=resource.id,

        presented_agent_code=payload.agent_code,

        action=action,
        destination=destination,

        authentication_status="SUCCESS",
        authorization_status="ALLOWED",

        decision="ALLOW",
        status="COMPLETED"
    )

    db.add(access_request)
    db.commit()

    return AccessRequestResponse(
        request_code=request_code,

        agent_code=payload.agent_code,
        resource_code=payload.resource_code,

        action=action,
        destination=destination,

        authentication_status="SUCCESS",
        authorization_status="ALLOWED",

        decision="ALLOW",

        reason=authorization_result["reason"],

        timestamp=datetime.now(
            timezone.utc
        )
    )