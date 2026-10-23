from datetime import datetime
from pydantic import BaseModel, Field, field_validator
from typing import Literal


class MetricLineage(BaseModel):
    metric_id: str
    value: float | int
    derived_from: list[str] = Field(min_length=1)
    framework_refs: list[str] = Field(default_factory=list)
    evidence_chain: list[str] = Field(min_length=1)
    timestamp: datetime
    verification_status: Literal["verified", "pending", "rejected"]
    calculation_method: str | None = None

    @field_validator("metric_id")
    @classmethod
    def metric_id_not_empty(cls, value: str):
        if not value.strip():
            raise ValueError("field cannot be empty")
        return value