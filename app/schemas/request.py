
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import (
    ActionType,
    DestinationType,
)


class AccessRequestCreate(BaseModel):
    agent_code: str
    credential: str = Field(repr=False)
    resource_code: str
    action: ActionType
    destination: DestinationType = (
        DestinationType.INTERNAL
    )

    # Required for WRITE and UPDATE.
    # Optional for other actions.
    payload_data: dict[str, Any] | None = None


class ContextAnalysisResponse(BaseModel):
    requests_last_minute: int
    recent_request_count: int
    high_frequency: bool
    external_destination: bool
    repeated_resource_access: bool
    repeated_action: bool
    suspicious_action_combination: bool
    suspicious_sequence: bool
    unusual_time: bool
    recent_denied_count: int
    multiple_recent_denials: bool
    unusual_activity: bool


class RiskFactorResponse(BaseModel):
    factor: str
    points: int


class AccessRequestResponse(BaseModel):
    request_code: str
    agent_code: str
    resource_code: str
    action: str
    destination: str

    authentication_status: str
    authorization_status: str

    resource_sensitivity: str | None = None
    context: ContextAnalysisResponse | None = None

    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    risk_factors: list[RiskFactorResponse]

    decision: str
    reason: str
    status: str
    timestamp: datetime
