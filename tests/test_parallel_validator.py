from parallel_validator import validate_parallel_evidence


def test_unbound_validator_blocks():
    result = validate_parallel_evidence(bundle={}, trusted_keys={"k": "pub"}, validator=None)
    assert result.status == "blocked"
    assert result.reason_code == "VALIDATOR_UNBOUND"


def test_empty_trust_store_denied():
    result = validate_parallel_evidence(bundle={}, trusted_keys={}, validator=lambda *_args, **_kw: {})
    assert result.status == "denied"


def test_signed_validator_receipt_passes():
    def validator(bundle, trusted_keys):
        assert trusted_keys == {"owner-key": "public-key"}
        return {"result": "validated", "run_id": "run-1", "evidence_hash": "a" * 64}
    result = validate_parallel_evidence(
        bundle={"evidence": []}, trusted_keys={"owner-key": "public-key"}, validator=validator
    )
    assert result.status == "pass"
    assert result.run_id == "run-1"


def test_claimed_pass_without_receipt_fails():
    result = validate_parallel_evidence(
        bundle={}, trusted_keys={"k": "pub"},
        validator=lambda *_args, **_kw: {"result": "validated", "run_id": "", "evidence_hash": "x"}
    )
    assert result.status == "failed"
