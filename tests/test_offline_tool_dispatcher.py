from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.offline_tool_dispatcher import (
    DurableSCARLedger,
    Ed25519RootOfTrust,
    SCARLedgerError,
    execute_tool_call,
)


@pytest.fixture
def ledger(tmp_path: Path):
    signer = Ed25519RootOfTrust(Ed25519PrivateKey.generate())
    return DurableSCARLedger(tmp_path / "scar" / "events.jsonl", "test-device", signer)


def test_allowlisted_echo_executes_and_is_signed(ledger):
    result = execute_tool_call(
        {"tool": "echo", "args": ["air-gapped", "execution"], "request_id": "r-1"},
        ledger=ledger,
    )
    assert result["status"] == "success"
    assert result["stdout"] == "air-gapped execution\n"
    assert result["scar"]["sequence"] == 0
    assert ledger.verify_chain()[0] is True


def test_unknown_tool_is_denied_and_audited(ledger):
    result = execute_tool_call({"tool": "python", "args": ["-c", "print(1)"]}, ledger=ledger)
    assert result["status"] == "denied"
    assert result["reason"] == "tool is not allowlisted"
    assert ledger.verify_chain()[1] == 1


@pytest.mark.parametrize(
    "request",
    [
        {"tool": "echo", "args": "not-a-list"},
        {"tool": "echo", "args": [1]},
        {"tool": "echo", "args": ["x"] * 9},
        {"tool": "echo", "args": ["x" * 1025]},
        {"tool": "echo", "args": ["bad\x00arg"]},
        {"tool": "echo", "args": [], "executable": "/bin/sh"},
    ],
)
def test_malformed_or_unsafe_requests_are_denied_and_audited(ledger, request):
    result = execute_tool_call(request, ledger=ledger)
    assert result["status"] == "denied"
    assert ledger.verify_chain()[1] == 1


def test_event_tampering_breaks_chain(ledger):
    execute_tool_call({"tool": "echo", "args": ["one"]}, ledger=ledger)
    event = json.loads(ledger.path.read_text(encoding="utf-8"))
    event["metadata"]["status"] = "tampered"
    ledger.path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    with pytest.raises(SCARLedgerError):
        ledger.verify_chain()


def test_signing_key_permissions_are_enforced(tmp_path):
    key_path = tmp_path / "unsafe.key"
    key_path.write_bytes(b"x" * 32)
    key_path.chmod(0o644)
    with pytest.raises(SCARLedgerError, match="permissions"):
        Ed25519RootOfTrust.from_file(key_path)


def test_ledger_rejects_incomplete_tail(ledger):
    execute_tool_call({"tool": "echo", "args": ["one"]}, ledger=ledger)
    with ledger.path.open("ab") as stream:
        stream.write(b'{"partial":')
    with pytest.raises(SCARLedgerError, match="incomplete final line"):
        ledger.verify_chain()


def test_audit_failure_withholds_tool_output(tmp_path):
    class BrokenLedger:
        def append(self, event_type, metadata):
            raise SCARLedgerError("disk unavailable")

    result = execute_tool_call({"tool": "echo", "args": ["must-not-release"]}, ledger=BrokenLedger())
    assert result["status"] == "blocked"
    assert "stdout" not in result


def test_chain_is_append_only_and_sequential(ledger):
    first = execute_tool_call({"tool": "echo", "args": ["one"]}, ledger=ledger)
    second = execute_tool_call({"tool": "echo", "args": ["two"]}, ledger=ledger)
    assert first["scar"]["sequence"] == 0
    assert second["scar"]["sequence"] == 1
    valid, count, _ = ledger.verify_chain()
    assert valid and count == 2
