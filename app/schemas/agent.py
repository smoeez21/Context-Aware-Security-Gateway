from pydantic import BaseModel, ConfigDict
from datetime import datetime


class AgentBase(BaseModel):
    agent_code: str
    name: str
    department: str
    role: str
    status: str = "ACTIVE"


class AgentCreate(AgentBase):
    credential: str


class AgentResponse(AgentBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)