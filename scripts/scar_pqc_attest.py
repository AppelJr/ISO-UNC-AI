#!/usr/bin/env python3
"""SCAR record-chain verifier.

This module verifies canonical SHA-256 record hashes and predecessor links.
It does NOT claim to verify ML-DSA/Falcon signatures, hardware attestation,
remote feed authenticity, or immutable storage. Those require separately
configured trust anchors and verifier backends; absent backends must not be
represented as PQC verification success.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any


SCAR_DIR_CANDIDATES = (
    pathlib.Path("scar"),
    pathlib.Path("SCAR"),
    pathlib.Path("evidence/scar"),
    pathlib.Path("logs/scar"),
)


class ScarVerificationError(ValueError):
    """Raised when SCAR evidence is missing, malformed, or inconsistent."""


def canonical_json(value: Any) -> bytes:
    """Return the single canonical encoding used for SCAR record hashes."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def verify_records(directory: pathlib.Path) -> int:
    """Verify every JSON record in lexical path order and return record count."""
    if not directory.is_dir():
        raise ScarVerificationError(f"SCAR directory does not exist: {directory}")

    records = sorted(directory.rglob("*.json"))
    if not records:
        raise ScarVerificationError(f"no SCAR JSON records found in {directory}")

    previous_hash: str | None = None
    for index, path in enumerate(records):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ScarVerificationError(f"cannot parse {path}: {exc}") from exc

        if not isinstance(data, dict):
            raise ScarVerificationError(f"record must be a JSON object: {path}")

        if index == 0:
            if data.get("hash_prev") not in (None, ""):
                raise ScarVerificationError(
                    f"first record must not reference a predecessor: {path}"
                )
        elif data.get("hash_prev") != previous_hash:
            raise ScarVerificationError(f"predecessor hash mismatch: {path}")

        declared_hash = data.get("record_hash")
        if not isinstance(declared_hash, str) or len(declared_hash) != 64:
            raise ScarVerificationError(f"missing/invalid record_hash: {path}")
        try:
            int(declared_hash, 16)
        except ValueError as exc:
            raise ScarVerificationError(f"record_hash is not hexadecimal: {path}") from exc

        unhashed = dict(data)
        unhashed.pop("record_hash", None)
        actual_hash = hashlib.sha256(canonical_json(unhashed)).hexdigest()
        if declared_hash != actual_hash:
            raise ScarVerificationError(f"record hash mismatch: {path}")

        previous_hash = declared_hash

    return len(records)


def locate_scar_directory() -> pathlib.Path:
    """Resolve exactly one conventional SCAR directory; ambiguity fails closed."""
    found = [candidate for candidate in SCAR_DIR_CANDIDATES if candidate.is_dir()]
    if len(found) != 1:
        raise ScarVerificationError(
            f"expected exactly one SCAR directory; found {len(found)}"
        )
    return found[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        type=pathlib.Path,
        help="explicit SCAR records directory; otherwise discover conventional path",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run a local positive/negative test of canonical hash verification",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="scar-self-test-") as temp:
            directory = pathlib.Path(temp)
            record = {"event": "self-test", "hash_prev": None}
            record["record_hash"] = hashlib.sha256(canonical_json(record)).hexdigest()
            (directory / "0001.json").write_text(
                json.dumps(record), encoding="utf-8"
            )
            # Hash is over the object with record_hash omitted.
            record_without_hash = dict(record)
            record_without_hash.pop("record_hash")
            record["record_hash"] = hashlib.sha256(
                canonical_json(record_without_hash)
            ).hexdigest()
            (directory / "0001.json").write_text(
                json.dumps(record), encoding="utf-8"
            )
            if verify_records(directory) != 1:
                raise ScarVerificationError("positive self-test failed")
            record["event"] = "tampered"
            (directory / "0001.json").write_text(
                json.dumps(record), encoding="utf-8"
            )
            try:
                verify_records(directory)
            except ScarVerificationError:
                print("SCAR_SELF_TEST=PASS")
                return 0
            raise ScarVerificationError("tamper negative self-test did not fail")

    directory = args.directory or locate_scar_directory()
    count = verify_records(directory)
    print(f"SCAR_CHAIN=PASS records={count}")
    print("SCAR_CRYPTO_SCOPE=HASH_CHAIN_ONLY; PQC/HARDWARE/IMMUTABILITY NOT VERIFIED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ScarVerificationError as exc:
        print(f"SCAR_CHAIN=FAIL {exc}", file=sys.stderr)
        raise SystemExit(1)
