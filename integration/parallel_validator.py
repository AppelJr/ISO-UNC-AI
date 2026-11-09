"""Fail-closed bridge to ISO-UNC-AI's signed evidence-bundle validator.

The validator and trusted-key store are injected by the application boundary.
This module never trusts a PASS string or bundle-supplied public key.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class ParallelValidationResult:
    status: str
    run_id: str | None
    evidence_hash: str | None
    reason_code: str


def validate_parallel_evidence(
    *,
    bundle: Mapping[str, Any],
    trusted_keys: Mapping[str, str],
    validator: Callable[..., Mapping[str, Any]] | None,
) -> ParallelValidationResult:
    if validator is None or not callable(validator):
        return ParallelValidationResult("blocked", None, None, "VALIDATOR_UNBOUND")
    if not isinstance(bundle, Mapping) or not isinstance(trusted_keys, Mapping) or not trusted_keys:
        return ParallelValidationResult("denied", None, None, "INVALID_INPUT")
    try:
        result = validator(dict(bundle), trusted_keys=dict(trusted_keys))
    except Exception:
        return ParallelValidationResult("failed", None, None, "EVIDENCE_VALIDATION_FAILED")
    if not isinstance(result, Mapping) or result.get("result") != "validated":
        return ParallelValidationResult("failed", None, None, "VALIDATOR_DID_NOT_CONFIRM")
    run_id = result.get("run_id")
    evidence_hash = result.get("evidence_hash")
    if not isinstance(run_id, str) or not run_id or not isinstance(evidence_hash, str) or len(evidence_hash) != 64:
        return ParallelValidationResult("failed", None, None, "MALFORMED_VALIDATOR_RECEIPT")
    return ParallelValidationResult("pass", run_id, evidence_hash, "SIGNED_BUNDLE_VALIDATED")
