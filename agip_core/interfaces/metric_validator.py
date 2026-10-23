from typing import Protocol
from agip_core.domain.metric import MetricLineage


class MetricValidatorProtocol(Protocol):
    def validate(self, metric: MetricLineage, evidence_store: dict, mappings: dict, alignments: dict) -> MetricLineage: ...