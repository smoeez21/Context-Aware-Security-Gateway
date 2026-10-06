from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import (
    ActionType,
    DestinationType,
)


class AccessRequestCreate(BaseModel):
    agent_code: str
    credential: str
    resource_code: str
    action: ActionType
    destination: DestinationType = DestinationType.INTERNAL


class AccessRequestResponse(BaseModel):
    request_code: str
    agent_code: str
    resource_code: str
    action: str
    destination: str

    authentication_status: str
    authorization_status: str

    decision: str
    reason: str

    timestamp: datetime