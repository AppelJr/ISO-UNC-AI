# Compliance & NIDS Integration Notes

This directory contains artifacts to help integrate the AI System Validator with enterprise NIDS/IDS and to document compliance alignment.

## Contents
- `schemas/validator_log_schema.json` — JSON Schema for audit manifests and logs (NIDS-friendly).
- `snort_example.rules` — Example Snort/Suricata IDS rule(s) to detect suspicious validator output patterns or unusual pipeline events (reference only).
- Guidance below on integrating with existing SIEM/NIDS.

## Integration guidance
1. **Log Format**  
   - The validator writes an `audit-manifest.json` (JSON) and `audit-log.jsonl` (line-delimited JSON). Each entry conforms to `validator_log_schema.json`. Ingest these logs into your SIEM (Splunk/ELK) for correlation.

2. **Alerting**  
   - Use the `event.type` and `score` fields to trigger NIDS/SIEM alerts. For example, a `score >= 0.7` anomaly may create a 'HIGH' alert severity.

3. **NIDS Rule Example**  
   - The included `snort_example.rules` is a conservative, non-destructive example illustrating how to detect suspicious outbound indicators if the validator is used in a monitored environment.

4. **Operational Notes**  
   - Keep validator output directories readable by your SIEM collector but restrict write access to operators.  
   - Do not store unencrypted sensitive artifacts in the same directory as the logs. Use vendor-approved encrypted channels if transmitting artifacts.

## Recommended Workflow
1. Run validator on a clean analysis host (offline where possible).  
2. Generate `audit-manifest.json` and `audit-log.jsonl`.  
3. Transfer only hashed manifests to SIEM via secured channel. If SIEM needs raw artifacts, vendor or legal should request them via secure exchange (PGP/SFTP).  
4. If SIEM correlates a true positive, escalate to IR per your playbooks — do not execute automated remediation from this validator.

## Contact / Compliance Owner
- Project: AI System Validator (Appel420)  
- For questions about the schema or NIDS rules, open a GitHub Discussion or issue.