from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import (
    ActionType,
    DestinationType,
)


# ============================================================
# ACCESS REQUEST INPUT
# ============================================================

class AccessRequestCreate(BaseModel):

    agent_code: str

    credential: str

    resource_code: str

    action: ActionType

    destination: DestinationType = (
        DestinationType.INTERNAL
    )


# ============================================================
# CONTEXT ANALYSIS RESPONSE
# ============================================================

class ContextAnalysisResponse(BaseModel):

    # Number of previous requests during last minute
    requests_last_minute: int

    # Number of previous requests during recent
    # five-minute analysis window
    recent_request_count: int

    # High request frequency detected
    high_frequency: bool

    # Request is going outside the organization
    external_destination: bool

    # Same resource accessed repeatedly
    repeated_resource_access: bool

    # Same action performed repeatedly
    repeated_action: bool

    # Suspicious combination such as
    # READ followed by external SEND
    suspicious_action_combination: bool

    # Suspicious resource sequence detected
    suspicious_sequence: bool

    # Request occurred during unusual hours
    unusual_time: bool

    # Number of recent blocked requests
    recent_denied_count: int

    # Three or more recent blocked attempts
    multiple_recent_denials: bool

    # Overall context anomaly indicator
    unusual_activity: bool


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

    # Resource classification
    resource_sensitivity: str | None = None

    # Context is only produced when appropriate
    context: ContextAnalysisResponse | None = None

    decision: str

    reason: str

    timestamp: datetime