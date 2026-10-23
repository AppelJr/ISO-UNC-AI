from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_spec = importlib.util.spec_from_file_location("sys_validator", Path("sys-validator.py"))
assert _spec is not None and _spec.loader is not None
_validator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_validator)
ValidationError = _validator.ValidationError
validate_bundle = _validator.validate_bundle


def _validate(bundle):
    # Tests inject a trust store explicitly; production must load it out of band.
    return validate_bundle(bundle, trusted_keys=bundle["trusted_keys"])

MODULES = (
    "core_tests",
    "extended_tests",
    "hardware_attestation",
    "threat_feed",
    "signature_update_vest",
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _make_bundle():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    trusted = {"test-root": base64.b64encode(public).decode()}
    evidence = []
    for index, module in enumerate(MODULES):
        payload = {"verified": True}
        if module == "hardware_attestation":
            payload.update({
                "attestation_type": "TPM2",
                "quote_digest": f"quote-{index}",
                "device_id_digest": f"device-{index}",
            })
        elif module == "threat_feed":
            payload.update({
                "feed_id": "test-feed",
                "feed_digest": "feed-digest",
                "source_verified": True,
                "target_clear": True,
            })
        elif module == "signature_update_vest":
            payload.update({"signature_fresh": True, "manifest_digest": "manifest-digest"})

        record = {
            "id": f"evidence-{index}",
            "module": module,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "pass",
            "payload": payload,
            "payload_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
        }
        signed = _canonical(record)
        record["signature"] = {
            "algorithm": "Ed25519",
            "key_id": "test-root",
            "value": base64.b64encode(private.sign(signed)).decode(),
        }
        evidence.append(record)

    return {
        "system_under_test": "security-fixture",
        "operator": "test",
        "trusted_keys": trusted,
        "evidence": evidence,
    }


def test_bundle_cannot_supply_its_own_trust_root():
    bundle = _make_bundle()
    with pytest.raises(ValidationError, match="external trusted_keys are required"):
        validate_bundle(bundle)


def test_valid_bundle_is_accepted():
    report = _validate(_make_bundle())
    assert report["result"] == "validated"
    assert list(report["modules"]) == list(MODULES)
    assert len(report["evidence_chain_digest"]) == 64


def test_payload_tampering_is_rejected():
    bundle = _make_bundle()
    bundle["evidence"][0]["payload"]["verified"] = False
    with pytest.raises(ValidationError, match="payload hash mismatch"):
        _validate(bundle)


def test_signature_tampering_is_rejected():
    bundle = _make_bundle()
    signature = bundle["evidence"][0]["signature"]["value"]
    raw = bytearray(base64.b64decode(signature))
    raw[0] ^= 1
    bundle["evidence"][0]["signature"]["value"] = base64.b64encode(raw).decode()
    with pytest.raises(ValidationError, match="signature verification failed"):
        _validate(bundle)


def test_stale_evidence_is_rejected():
    bundle = _make_bundle()
    bundle["evidence"][0]["timestamp"] = (
        datetime.now(timezone.utc) - timedelta(days=2)
    ).isoformat()
    with pytest.raises(ValidationError, match="stale"):
        _validate(bundle)


def test_future_evidence_is_rejected():
    bundle = _make_bundle()
    bundle["evidence"][0]["timestamp"] = (
        datetime.now(timezone.utc) + timedelta(minutes=10)
    ).isoformat()
    with pytest.raises(ValidationError, match="future"):
        _validate(bundle)


def test_missing_required_module_is_rejected():
    bundle = _make_bundle()
    bundle["evidence"].pop()
    with pytest.raises(ValidationError, match="required evidence missing"):
        _validate(bundle)


def test_untrusted_signing_key_is_rejected():
    bundle = _make_bundle()
    bundle["evidence"][0]["signature"]["key_id"] = "untrusted"
    with pytest.raises(ValidationError, match="not trusted"):
        _validate(bundle)


def test_duplicate_module_evidence_is_rejected():
    bundle = _make_bundle()
    bundle["evidence"].append(dict(bundle["evidence"][0]))
    with pytest.raises(ValidationError, match="duplicate evidence"):
        _validate(bundle)
