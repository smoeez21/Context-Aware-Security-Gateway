from pydantic import BaseModel, ConfigDict
from datetime import datetime
from app.schemas.common import (
    ActionType,
    DestinationType,
    PolicyEffect,
)

class PolicyCreate(BaseModel):
    agent_id: int
    resource_id: int
    action: ActionType
    destination: DestinationType = DestinationType.INTERNAL
    effect: PolicyEffect
    description: str | None = None

class PolicyResponse(BaseModel):
    id: int
    agent_id: int
    resource_id: int
    action: str
    destination: str
    effect: str
    description: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)