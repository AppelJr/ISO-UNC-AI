from agip_core.domain.metric import MetricLineage


class MetricLineageError(Exception):
    pass


class MetricValidator:
    def validate(self, metric: MetricLineage, evidence_store: dict, mappings: dict, alignments: dict) -> MetricLineage:
        if metric.verification_status != "verified":
            raise MetricLineageError("Unverified metrics cannot be published")
        if len(metric.derived_from) == 0:
            raise MetricLineageError("Metric requires control mapping lineage")
        for mapping_id in metric.derived_from:
            if mapping_id not in mappings:
                raise MetricLineageError(f"Missing control mapping: {mapping_id}")
        if len(metric.evidence_chain) == 0:
            raise MetricLineageError("Metric requires evidence chain")
        for evidence_id in metric.evidence_chain:
            evidence = evidence_store.get(evidence_id)
            if evidence is None:
                raise MetricLineageError(f"Missing evidence: {evidence_id}")
            if evidence.verification_status != "verified":
                raise MetricLineageError(f"Evidence not verified: {evidence_id}")
        for framework in metric.framework_refs:
            if framework not in alignments:
                raise MetricLineageError(f"Missing framework alignment: {framework}")
        return metric