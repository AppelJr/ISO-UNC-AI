#!/usr/bin/env python3
"""Air-gapped, allowlisted local tool dispatcher with signed SCAR evidence.

Model output is an untrusted request, never an executable path. The dispatcher
selects fixed executables, validates bounded string arguments, runs without a
shell or inherited environment, and releases output only after the signed
append-only SCAR event has been fsynced.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import secrets
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol
from uuid import uuid4

MAX_INPUT_BYTES = 16 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
TIMEOUT_SECONDS = 5
POLICY_VERSION = "offline-tool-dispatcher/2.0.0"
GENESIS_EVENT_HASH = "0" * 64

# Executables are deployment policy. Never accept an executable path from a
# request. Extend this map only through reviewed code changes and tests.
TOOLS: dict[str, dict[str, Any]] = {
    "echo": {
        "executable": "/bin/echo",
        "max_args": 8,
        "max_arg_length": 1024,
    },
}


class DispatcherError(RuntimeError):
    """Raised when a request cannot safely be processed."""


class SCARLedgerError(RuntimeError):
    """Raised when signed, durable SCAR evidence cannot be established."""


class RootOfTrust(Protocol):
    def sign(self, payload: bytes) -> bytes: ...
    def verify(self, payload: bytes, signature: bytes) -> None: ...


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class Ed25519RootOfTrust:
    """Ed25519 signer/verifier. Verification may use an independently provisioned public key."""

    private_key: Any | None = None
    public_key: Any | None = None

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "Ed25519RootOfTrust":
        try:
            if path.is_symlink():
                raise SCARLedgerError("signing key must not be a symlink")
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise SCARLedgerError("signing key must be a regular file")
            if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
                raise SCARLedgerError("signing key permissions must be 0600 or stricter")
            raw = path.read_bytes()
            if len(raw) != 32:
                raise SCARLedgerError("Ed25519 private key must be exactly 32 raw bytes")
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            private = Ed25519PrivateKey.from_private_bytes(raw)
            return cls(private_key=private, public_key=private.public_key())
        except OSError as exc:
            raise SCARLedgerError(f"cannot load signing key: {exc}") from exc

    @classmethod
    def from_public_file(cls, path: pathlib.Path) -> "Ed25519RootOfTrust":
        try:
            if path.is_symlink():
                raise SCARLedgerError("verification key must not be a symlink")
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise SCARLedgerError("verification key must be a regular file")
            raw = path.read_bytes()
            if len(raw) != 32:
                raise SCARLedgerError("Ed25519 public key must be exactly 32 raw bytes")
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            return cls(public_key=Ed25519PublicKey.from_public_bytes(raw))
        except OSError as exc:
            raise SCARLedgerError(f"cannot load verification key: {exc}") from exc

    def sign(self, payload: bytes) -> bytes:
        if self.private_key is None:
            raise SCARLedgerError("private signing key is unavailable")
        return self.private_key.sign(payload)

    def verify(self, payload: bytes, signature: bytes) -> None:
        try:
            if self.public_key is None:
                raise SCARLedgerError("public verification key is unavailable")
            self.public_key.verify(signature, payload)
        except Exception as exc:
            raise SCARLedgerError("SCAR signature verification failed") from exc

    def write_public_key(self, path: pathlib.Path) -> None:
        if self.private_key is None:
            raise SCARLedgerError("private signing key is unavailable")
        from cryptography.hazmat.primitives import serialization
        raw = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        _write_exclusive(path, raw, 0o644)


def _write_exclusive(path: pathlib.Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


class DurableSCARLedger:
    """Signed SHA-256 hash chain, append-only JSONL, locked and fsynced."""

    def __init__(self, path: pathlib.Path, identity_id: str, signer: RootOfTrust):
        if not identity_id.strip():
            raise ValueError("identity_id must not be empty")
        self.path = path
        self.identity_id = identity_id
        self.signer = signer

    def _read_and_verify(self) -> tuple[int, str]:
        if self.path.is_symlink():
            raise SCARLedgerError("SCAR ledger must not be a symlink")
        if not self.path.exists():
            return 0, GENESIS_EVENT_HASH
        if not self.path.is_file():
            raise SCARLedgerError("SCAR ledger path must be a regular file")
        previous = GENESIS_EVENT_HASH
        count = 0
        try:
            with self.path.open("rb") as stream:
                for line_number, raw_line in enumerate(stream, 1):
                    if not raw_line.endswith(b"\n"):
                        raise SCARLedgerError(
                            f"SCAR ledger has incomplete final line at {line_number}"
                        )
                    try:
                        event = json.loads(raw_line)
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        raise SCARLedgerError(
                            f"invalid SCAR JSON at line {line_number}"
                        ) from exc
                    if not isinstance(event, dict):
                        raise SCARLedgerError(f"SCAR event is not an object at line {line_number}")
                    signature_hex = event.pop("signature", None)
                    event_hash = event.pop("event_hash", None)
                    if event.get("sequence") != count:
                        raise SCARLedgerError(f"SCAR sequence mismatch at line {line_number}")
                    if event.get("previous_event_hash") != previous:
                        raise SCARLedgerError(f"SCAR predecessor mismatch at line {line_number}")
                    if event.get("identity_id") != self.identity_id:
                        raise SCARLedgerError(f"SCAR identity mismatch at line {line_number}")
                    if not isinstance(signature_hex, str) or not isinstance(event_hash, str):
                        raise SCARLedgerError(f"SCAR signature/hash missing at line {line_number}")
                    try:
                        signature = bytes.fromhex(signature_hex)
                        computed_hash = sha256_hex(
                            canonical_bytes({"document": event, "signature": signature_hex})
                        )
                        self.signer.verify(canonical_bytes(event), signature)
                    except (ValueError, TypeError) as exc:
                        raise SCARLedgerError(f"invalid SCAR encoding at line {line_number}") from exc
                    if not secrets.compare_digest(computed_hash, event_hash):
                        raise SCARLedgerError(f"SCAR event hash mismatch at line {line_number}")
                    previous = event_hash
                    count += 1
        except OSError as exc:
            raise SCARLedgerError(f"cannot read SCAR ledger: {exc}") from exc
        return count, previous

    def append(self, event_type: str, metadata: Mapping[str, Any]) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise SCARLedgerError("SCAR ledger must not be a symlink")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self.path, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "ab") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                sequence, previous = self._read_and_verify()
                document = {
                    "sequence": sequence,
                    "event_id": str(uuid4()),
                    "event_type": event_type,
                    "timestamp": utc_timestamp(),
                    "identity_id": self.identity_id,
                    "actor": "system",
                    "event_class": "security" if event_type != "TOOL_CALL" else "audit",
                    "previous_event_hash": previous,
                    "metadata": dict(metadata),
                }
                signature = self.signer.sign(canonical_bytes(document)).hex()
                event_hash = sha256_hex(
                    canonical_bytes({"document": document, "signature": signature})
                )
                event = {**document, "signature": signature, "event_hash": event_hash}
                stream.write(canonical_bytes(event) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                return event
        except (OSError, ValueError) as exc:
            raise SCARLedgerError(f"SCAR append failed: {exc}") from exc

    def verify_chain(self) -> tuple[bool, int, str]:
        count, final_hash = self._read_and_verify()
        return True, count, final_hash


def _bounded_text(value: str, limit: int) -> str:
    encoded = value.encode("utf-8")
    return encoded[:limit].decode("utf-8", errors="replace")


def _request_digest(tool: str, args: list[str]) -> str:
    return sha256_hex(canonical_bytes({"tool": tool, "args": args}))


def execute_tool_call(
    request: Any,
    *,
    ledger: DurableSCARLedger,
    timeout_seconds: int = TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Execute exactly one allowlisted local request and record its outcome."""
    timestamp = utc_timestamp()
    if not isinstance(request, dict):
        raise DispatcherError("request must be a JSON object")
    if set(request) - {"tool", "args", "request_id"}:
        raise DispatcherError("request contains unsupported fields")

    tool_name = request.get("tool")
    args = request.get("args", [])
    request_id = request.get("request_id")
    if request_id is not None and (
        not isinstance(request_id, str) or len(request_id) > 128
    ):
        raise DispatcherError("request_id must be a string of at most 128 characters")

    status = "denied"
    reason = None
    returncode = None
    stdout = ""
    stderr = ""
    tool_policy = TOOLS.get(tool_name) if isinstance(tool_name, str) else None
    if tool_policy is None:
        reason = "tool is not allowlisted"
    elif not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        reason = "args must be a list of strings"
    elif len(args) > tool_policy["max_args"]:
        reason = "too many arguments"
    elif any(len(arg) > tool_policy["max_arg_length"] for arg in args):
        reason = "argument exceeds length limit"
    elif any("\x00" in arg for arg in args):
        reason = "NUL bytes are not permitted in arguments"
    else:
        executable = tool_policy["executable"]
        if not os.path.isabs(executable) or not os.path.isfile(executable) or not os.access(executable, os.X_OK):
            reason = "configured executable is unavailable or not executable"
        else:
            try:
                result = subprocess.run(
                    [executable, *args],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout_seconds,
                    check=False,
                    shell=False,
                    close_fds=True,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
                stdout = _bounded_text(result.stdout, MAX_OUTPUT_BYTES)
                stderr = _bounded_text(result.stderr, MAX_OUTPUT_BYTES)
                returncode = result.returncode
                status = "success" if returncode == 0 else "error"
                if status == "error":
                    reason = "tool returned a non-zero exit code"
            except subprocess.TimeoutExpired:
                status, reason = "error", "tool timed out"
            except OSError as exc:
                status, reason = "error", f"tool execution failed: {type(exc).__name__}"

    safe_args = args if isinstance(args, list) and all(isinstance(x, str) for x in args) else []
    metadata = {
        "policy_version": POLICY_VERSION,
        "request_id": request_id,
        "tool": tool_name if isinstance(tool_name, str) else None,
        "request_sha256": _request_digest(
            tool_name if isinstance(tool_name, str) else "<invalid>", safe_args
        ),
        "status": status,
        "reason": reason,
        "returncode": returncode,
        "stdout_sha256": sha256_hex(stdout.encode("utf-8")),
        "stderr_sha256": sha256_hex(stderr.encode("utf-8")),
        "output_truncated": (
            len(stdout.encode("utf-8")) >= MAX_OUTPUT_BYTES
            or len(stderr.encode("utf-8")) >= MAX_OUTPUT_BYTES
        ),
    }
    try:
        receipt = ledger.append("TOOL_CALL", metadata)
    except SCARLedgerError:
        return {
            "timestamp": timestamp,
            "status": "blocked",
            "reason": "SCAR append failed; output withheld",
            "tool": metadata["tool"],
        }

    return {
        "timestamp": timestamp,
        "status": status,
        "tool": metadata["tool"],
        "request_id": request_id,
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "reason": reason,
        "scar": {
            "sequence": receipt["sequence"],
            "event_id": receipt["event_id"],
            "event_hash": receipt["event_hash"],
        },
    }


def load_request(stream: Any) -> Any:
    raw = stream.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise DispatcherError("request exceeds maximum input size")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DispatcherError("invalid JSON input") from exc


def generate_signing_key(private_path: pathlib.Path, public_path: pathlib.Path) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    _write_exclusive(private_path, private_raw, 0o600)
    try:
        _write_exclusive(public_path, public_raw, 0o644)
    except Exception:
        private_path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-log", type=pathlib.Path, default=pathlib.Path("var/scar/offline-tools.jsonl"))
    parser.add_argument("--identity-id", default="local-device")
    parser.add_argument("--signing-key", type=pathlib.Path)
    parser.add_argument("--verification-key", type=pathlib.Path)
    parser.add_argument("--generate-key", type=pathlib.Path, metavar="PRIVATE_KEY")
    parser.add_argument("--public-key", type=pathlib.Path)
    parser.add_argument("--verify", action="store_true", help="verify the existing signed SCAR chain")
    args = parser.parse_args(argv)

    try:
        if args.generate_key:
            if not args.public_key:
                raise DispatcherError("--public-key is required with --generate-key")
            generate_signing_key(args.generate_key, args.public_key)
            print(json.dumps({"status": "success", "private_key": str(args.generate_key), "public_key": str(args.public_key)}))
            return 0
        if args.verify:
            if not args.verification_key:
                raise DispatcherError("--verification-key is required for independent chain verification")
            verifier = Ed25519RootOfTrust.from_public_file(args.verification_key)
            ledger = DurableSCARLedger(args.audit_log, args.identity_id, verifier)
            valid, count, final_hash = ledger.verify_chain()
            print(json.dumps({"status": "success", "chain": "PASS", "records": count, "final_hash": final_hash}))
            return 0
        if not args.signing_key:
            raise DispatcherError("--signing-key is required; unsigned execution is prohibited")
        signer = Ed25519RootOfTrust.from_file(args.signing_key)
        ledger = DurableSCARLedger(args.audit_log, args.identity_id, signer)
        request = load_request(sys.stdin)
        response = execute_tool_call(request, ledger=ledger)
        print(json.dumps(response, ensure_ascii=False, indent=2))
        return 0 if response["status"] == "success" else 1
    except (DispatcherError, SCARLedgerError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
