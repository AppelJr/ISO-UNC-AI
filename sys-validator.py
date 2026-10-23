#!/usr/bin/env python3
"""ISO-UNC-AI evidence validator.

This validator never treats a declared status as proof. Every required module
must provide a signed, hash-bound evidence record. Missing, stale, malformed,
unsigned, or unverifiable evidence fails closed.

The validator is deliberately offline-first: it validates a supplied evidence
bundle and does not silently fetch network data or infer hardware trust.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - exercised by the CI dependency gate
    InvalidSignature = Exception
    Ed25519PublicKey = None
    serialization = None

MODULES = (
    "core_tests",
    "extended_tests",
    "hardware_attestation",
    "threat_feed",
    "signature_update_vest",
)
MAX_CLOCK_SKEW_SECONDS = 300


class ValidationError(ValueError):
    """A fail-closed validation error."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValidationError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _decode_b64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValidationError("invalid base64 encoding") from exc


def _load_public_key(value: str) -> Any:
    if Ed25519PublicKey is None or serialization is None:
        raise ValidationError("cryptography dependency unavailable")
    raw = value.encode()
    try:
        if value.startswith("-----BEGIN"):
            return serialization.load_pem_public_key(raw)
        decoded = _decode_b64(value)
        if len(decoded) != 32:
            raise ValidationError("Ed25519 public key must be 32 bytes")
        return Ed25519PublicKey.from_public_bytes(decoded)
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError("invalid Ed25519 public key") from exc


def _verify_evidence(evidence: dict[str, Any], trusted_keys: dict[str, str]) -> None:
    required = {"id", "module", "timestamp", "status", "payload", "payload_sha256", "signature"}
    missing = required - evidence.keys()
    if missing:
        raise ValidationError(f"evidence missing fields: {sorted(missing)}")
    if evidence["status"] != "pass":
        raise ValidationError(f"module status is {evidence['status']!r}")
    if evidence["module"] not in MODULES:
        raise ValidationError("unknown module")
    timestamp = _parse_time(evidence["timestamp"])
    if (_utc_now() - timestamp).total_seconds() < -MAX_CLOCK_SKEW_SECONDS:
        raise ValidationError("evidence timestamp is from the future")
    if ( _utc_now() - timestamp).total_seconds() > 86400:
        raise ValidationError("evidence is stale")
    if _sha256(evidence["payload"]) != evidence["payload_sha256"]:
        raise ValidationError("evidence payload hash mismatch")

    signature = evidence["signature"]
    if not isinstance(signature, dict) or signature.get("algorithm") != "Ed25519":
        raise ValidationError("unsupported or missing signature algorithm")
    key_id = signature.get("key_id")
    if key_id not in trusted_keys:
        raise ValidationError("signing key is not trusted")
    key = _load_public_key(trusted_keys[key_id])
    signed = _canonical_json({
        "id": evidence["id"],
        "module": evidence["module"],
        "timestamp": evidence["timestamp"],
        "status": evidence["status"],
        "payload": evidence["payload"],
        "payload_sha256": evidence["payload_sha256"],
    })
    try:
        key.verify(_decode_b64(signature["value"]), signed)
    except InvalidSignature as exc:
        raise ValidationError("evidence signature verification failed") from exc


def _validate_module_payload(module: str, payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise ValidationError(f"{module}: payload must be an object")
    if payload.get("verified") is not True:
        raise ValidationError(f"{module}: verified=true is required")

    if module == "hardware_attestation":
        if payload.get("attestation_type") not in {"TPM2", "SecureEnclave", "TEE"}:
            raise ValidationError("hardware_attestation: unsupported attestation type")
        if not payload.get("quote_digest"):
            raise ValidationError("hardware_attestation: quote_digest required")
        if not payload.get("device_id_digest"):
            raise ValidationError("hardware_attestation: device_id_digest required")

    if module == "threat_feed":
        if not payload.get("feed_id") or not payload.get("feed_digest"):
            raise ValidationError("threat_feed: feed_id and feed_digest required")
        if payload.get("source_verified") is not True:
            raise ValidationError("threat_feed: source_verified=true required")
        if payload.get("target_clear") is not True:
            raise ValidationError("threat_feed: target_clear=true required")

    if module == "signature_update_vest":
        if payload.get("signature_fresh") is not True:
            raise ValidationError("signature_update_vest: signature_fresh=true required")
        if not payload.get("manifest_digest"):
            raise ValidationError("signature_update_vest: manifest_digest required")


def validate_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        raise ValidationError("bundle must be an object")
    target = bundle.get("system_under_test")
    evidence = bundle.get("evidence")
    trusted_keys = bundle.get("trusted_keys")
    if not isinstance(target, str) or not target:
        raise ValidationError("system_under_test is required")
    if not isinstance(evidence, list):
        raise ValidationError("evidence array is required")
    if not isinstance(trusted_keys, dict) or not trusted_keys:
        raise ValidationError("trusted_keys is required")

    by_module: dict[str, dict[str, Any]] = {}
    for record in evidence:
        if not isinstance(record, dict):
            raise ValidationError("each evidence record must be an object")
        module = record.get("module")
        if module in by_module:
            raise ValidationError(f"duplicate evidence for module: {module}")
        _verify_evidence(record, trusted_keys)
        _validate_module_payload(module, record["payload"])
        by_module[module] = record

    missing = [module for module in MODULES if module not in by_module]
    if missing:
        raise ValidationError(f"required evidence missing: {missing}")

    ordered_ids = [by_module[module]["id"] for module in MODULES]
    chain_digest = hashlib.sha256("|".join(ordered_ids).encode()).hexdigest()
    modules = {module: "pass" for module in MODULES}
    return {
        "timestamp": _utc_now().isoformat(),
        "run_id": str(uuid.uuid4()),
        "operator": bundle.get("operator", "unspecified"),
        "system_under_test": target,
        "modules": modules,
        "result": "validated",
        "evidence_hash": _sha256(evidence),
        "evidence_chain_digest": chain_digest,
        "artifacts": [record["id"] for record in evidence],
    }


def validate_file(path: Path) -> dict[str, Any]:
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot load evidence bundle: {exc}") from exc
    return validate_bundle(bundle)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed ISO-UNC-AI evidence validator")
    parser.add_argument("bundle", nargs="?", type=Path, help="JSON evidence bundle")
    args = parser.parse_args(argv)
    if args.bundle is None:
        print(json.dumps({"result": "rejected", "reason": "evidence bundle required"}, indent=2))
        return 1
    try:
        report = validate_file(args.bundle)
    except ValidationError as exc:
        print(json.dumps({"result": "rejected", "reason": str(exc)}, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
