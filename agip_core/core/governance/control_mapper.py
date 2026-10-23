from agip_core.domain.control_mapping import ControlMapping
from agip_core.domain.evidence import Evidence


class ControlMappingError(Exception):
    pass


class ControlMapper:
    def validate(self, mapping: ControlMapping, evidence_store: dict[str, Evidence]):
        evidence = evidence_store.get(mapping.evidence_ref)
        if evidence is None:
            raise ControlMappingError("Evidence reference missing")
        if evidence.verification_status != "verified":
            raise ControlMappingError("Evidence is not verified")
        if mapping.status == "rejected":
            raise ControlMappingError("Rejected mapping")
        return mapping