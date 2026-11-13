# Offline Tool Dispatcher v2.0.0

A local execution boundary for air-gapped Sovereignty nodes. AI output is an
untrusted request; it never supplies an executable path, shell fragment, or
environment. The dispatcher resolves a fixed allowlist, validates arguments,
executes one bounded process without a shell, and writes a signed SCAR event
before releasing command output.

## Security contract

- Fixed absolute executable paths in \`TOOLS\`; requests cannot choose a binary.
- No \`shell=True\`, shell parsing, network transport, or inherited process environment.
- JSON-only request input, 16 KiB maximum.
- Per-tool argument count and length limits; NUL bytes rejected.
- Five-second execution timeout and 64 KiB output cap.
- stdin is \`/dev/null\`; file descriptors are closed; locale and PATH are fixed.
- Ed25519 signature plus SHA-256 predecessor chain; ledger append uses an exclusive
  file lock, append mode, \`fsync\`, and restrictive \`0600\` creation mode.
- Existing ledger records and signatures are verified before every append.
- If the SCAR append fails after execution, the dispatcher returns \`blocked\` and
  withholds stdout/stderr. The process may already have run; this is reported
  honestly and is not rolled back.
- No raw tool output or raw arguments are copied into SCAR metadata; their hashes
  are recorded instead.
- \`echo\` is the only default tool. Adding a tool requires a reviewed fixed-path
  policy entry and corresponding tests. Never add a generic shell, Python \`-c\`,
  arbitrary path, or unrestricted file-write tool.

## Key setup

Install the repository dependencies in the offline environment first. Generate
a device-local signing key once; store the private key outside the repository and
back it up using the device's approved key-custody procedure:

\`\`\`sh
python tools/offline_tool_dispatcher.py \\
  --generate-key /secure/path/scar-ed25519.key \\
  --public-key /secure/path/scar-ed25519.pub
chmod 600 /secure/path/scar-ed25519.key
\`\`\`

The key generator uses exclusive file creation and refuses to overwrite either
existing key. The private key must remain local. The public key is the verifier
trust anchor and must be provisioned independently to any verifier.

## Execute one local tool call

\`\`\`sh
printf '%s\\n' '{"tool":"echo","args":["air-gapped","execution"],"request_id":"demo-001"}' |
  python tools/offline_tool_dispatcher.py \\
    --signing-key /secure/path/scar-ed25519.key \\
    --audit-log /secure/path/scar/offline-tools.jsonl \\
    --identity-id device-unique-id
\`\`\`

A successful response contains stdout plus a SCAR event ID, sequence, and hash.
No network access is required. The default \`echo\` binary must exist at \`/bin/echo\`
on the target OS; a missing binary is a denial, not a PATH fallback.

## Verify the signed ledger

\`\`\`sh
python tools/offline_tool_dispatcher.py \\
  --signing-key /secure/path/scar-ed25519.key \\
  --audit-log /secure/path/scar/offline-tools.jsonl \\
  --identity-id device-unique-id \\
  --verify
\`\`\`

Verification checks sequence, identity, predecessor links, canonical event
hashes, and Ed25519 signatures. This is a local signer-backed ledger; it does
not by itself prove hardware-backed key custody, remote timestamping, PQC
attestation, or immutable storage.

## Request format

\`\`\`json
{
  "tool": "echo",
  "args": ["hello"],
  "request_id": "optional-correlation-id"
}
\`\`\`

Unknown fields and tools are rejected. This dispatcher executes one request per
process invocation. It is not an authorization engine: a valid local tool call
does not grant authority to modify repositories, change policy, access secrets,
or perform network operations.
