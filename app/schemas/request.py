
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import (
    ActionType,
    DestinationType,
)


# ============================================================
# ACCESS REQUEST INPUT
# ============================================================

class AccessRequestCreate(BaseModel):

    agent_code: str
    credential: str = Field(repr=False)
    resource_code: str

    action: ActionType

    destination: DestinationType = (
        DestinationType.INTERNAL
    )


# ============================================================
# CONTEXT ANALYSIS RESPONSE
# ============================================================

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


# ============================================================
# RISK FACTOR
# ============================================================

class RiskFactorResponse(BaseModel):

    factor: str
    points: int


# ============================================================
# ACCESS REQUEST RESPONSE
# ============================================================

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

    # Phase 6 additions
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    risk_factors: list[RiskFactorResponse]

    decision: str
    reason: str

    # Explains whether the request is waiting for execution,
    # blocked, or awaiting administrator review.
    status: str

    timestamp: datetime
