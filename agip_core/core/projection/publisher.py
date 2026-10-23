from agip_core.domain.metric import MetricLineage
from agip_core.core.governance.metric_validator import MetricValidator, MetricLineageError


class MetricPublisher:
    def __init__(self, validator: MetricValidator | None = None):
        self.validator = validator or MetricValidator()

    def publish_metric(self, metric: MetricLineage, evidence_store: dict, mappings: dict, alignments: dict) -> dict:
        validated = self.validator.validate(metric, evidence_store, mappings, alignments)
        if validated.verification_status != "verified":
            raise ValueError("Only verified metrics may be projected")
        return validated.model_dump()