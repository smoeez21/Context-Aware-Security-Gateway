from pydantic import BaseModel, ConfigDict
from datetime import datetime
from app.schemas.common import SensitivityLevel

class ResourceBase(BaseModel):
    resource_code: str
    name: str
    resource_type: str
    sensitivity: SensitivityLevel
    description: str | None = None


class ResourceCreate(ResourceBase):
    pass


class ResourceResponse(ResourceBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)