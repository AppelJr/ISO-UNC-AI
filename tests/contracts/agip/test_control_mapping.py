from agip_core.domain.control_mapping import ControlMapping
from agip_core.domain.evidence import Evidence
from agip_core.core.governance.control_mapper import ControlMapper


def test_mapping_requires_verified_evidence():
    mapping = ControlMapping(
        mapping_id="map_001",
        framework="nist_ai_rmf",
        function="measure",
        control_ref="NIST.AI.RMF.MEASURE",
        object_type="evidence",
        object_id="ev_001",
        evidence_ref="ev_001",
        status="mapped",
    )
    evidence_store = {
        "ev_001": Evidence(
            id="ev_001",
            source_id="src1",
            timestamp="2026-07-21T00:00:00Z",
            object_type="evidence",
            verification_status="verified",
            confidence=0.95,
        )
    }
    result = ControlMapper().validate(mapping, evidence_store)
    assert result.mapping_id == "map_001"