import pytest
from agip_core.domain.metric import MetricLineage


def test_metric_requires_evidence_chain():
    with pytest.raises(ValueError):
        MetricLineage(
            metric_id="ai_inventory_coverage",
            value=87,
            derived_from=["map_001"],
            framework_refs=["nist_ai_rmf"],
            evidence_chain=[],
            timestamp="2026-07-21T00:00:00Z",
            verification_status="verified",
        )