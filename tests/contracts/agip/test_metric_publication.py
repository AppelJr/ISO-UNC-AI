import pytest
from agip_core.domain.metric import MetricLineage
from agip_core.core.governance.metric_validator import MetricValidator, MetricLineageError


def _ev(status="verified"):
    return type("Evidence", (), {"verification_status": status})()


def test_unverified_metric_cannot_publish():
    metric = MetricLineage(
        metric_id="ai_inventory_coverage",
        value=87,
        derived_from=["map_001"],
        framework_refs=["nist_ai_rmf"],
        evidence_chain=["ev_001"],
        timestamp="2026-07-21T00:00:00Z",
        verification_status="pending",
    )
    with pytest.raises(MetricLineageError):
        MetricValidator().validate(metric, {"ev_001": _ev()}, {"map_001": {}}, {"nist_ai_rmf": {}})


def test_verified_metric_can_publish():
    metric = MetricLineage(
        metric_id="ai_inventory_coverage",
        value=87,
        derived_from=["map_001"],
        framework_refs=["nist_ai_rmf"],
        evidence_chain=["ev_001"],
        timestamp="2026-07-21T00:00:00Z",
        verification_status="verified",
    )
    out = MetricValidator().validate(metric, {"ev_001": _ev()}, {"map_001": {}}, {"nist_ai_rmf": {}})
    assert out.metric_id == "ai_inventory_coverage"