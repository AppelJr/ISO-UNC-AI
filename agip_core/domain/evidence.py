from pydantic import BaseModel, Field
from typing import Literal


class Evidence(BaseModel):
    id: str
    source_id: str
    timestamp: str
    object_type: str
    verification_status: Literal["verified", "pending", "rejected"]
    confidence: float = Field(ge=0.0, le=1.0)
    framework_refs: list[str] = Field(default_factory=list)