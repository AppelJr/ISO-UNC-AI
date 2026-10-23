from pydantic import BaseModel, Field


class FrameworkAlignment(BaseModel):
    alignment_id: str
    framework: str
    version: str
    enabled: bool
    control_mappings: list[str] = Field(min_length=1)
    description: str | None = None