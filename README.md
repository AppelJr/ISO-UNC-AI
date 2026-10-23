# AI System Validator

ISO-UNC-AI compliant AI system validation suite.

## What It Does

Validates AI systems across five modules: core tests, extended tests,
hardware attestation, threat feed cross-reference, and signature update
vest. Fail-closed by design — any module failure halts validation.

## Structure

- `sys-validator.py` — Python validation engine
- `validator.js` — JavaScript client-side checks
- `log-schema.js` — structured log output schema
- `SYSTEM_VALIDATOR.md` — compliance flowchart
- `validator_logic.yaml` — module stack definition
- `docs/` — extended documentation
- `templates/` — vendor disclosure and evidence manifest templates
- `.github/workflows/validate.yml` — CI validation workflow

## Compliance

- ISO/IEC 27037 (Evidence Handling)
- IEC 61508 (Functional Safety)
- NIST SP 800-53 PE-10 (Emergency Shutoff)
- UNC-AI-2026 Optional Protocol III

## License

MIT + Secure-Use Clause. See LICENSE.md.

## Operator

Appel420 / Ara — ISO-UNC-AI
