from pydantic import BaseModel
from typing import Literal


class ControlMapping(BaseModel):
    mapping_id: str
    framework: str
    function: Literal["govern", "map", "measure", "manage"]
    control_ref: str
    object_type: str
    object_id: str
    evidence_ref: str
    status: Literal["mapped", "verified", "rejected"]