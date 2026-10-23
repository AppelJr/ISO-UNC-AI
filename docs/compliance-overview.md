# Compliance Overview

## Standards Mapped

| Standard | Section | Coverage |
|----------|---------|----------|
| ISO/IEC 27037 | Evidence Handling | Full |
| IEC 61508 | Functional Safety | SIL 2 estimated |
| NIST SP 800-53 | PE-10 Emergency Shutoff | Referenced |
| UNC-AI-2026 | Optional Protocol III | Primary |

## Validation Pipeline

1. Core tests run first — baseline functional check.
2. Extended tests cover edge cases and stress.
3. Hardware attestation proves device identity.
4. Threat feed cross-references live CVEs.
5. Signature update vest confirms crypto freshness.

Any failure at any stage halts the pipeline. No partial pass.

## Evidence Artifacts

All validation runs produce structured logs per log-schema.js.
Evidence manifests are generated from templates/evidence-manifest.md.
