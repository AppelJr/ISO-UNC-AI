/**
 * ISO-UNC-AI Validator Log Schema
 * Structured output for all validation runs.
 */

const LogSchema = {
  version: "1.0",
  fields: {
    timestamp: "ISO-8601 UTC",
    run_id: "UUID",
    operator: "string",
    system_under_test: "string",
    modules: {
      core_tests: "pass | fail | skipped",
      extended_tests: "pass | fail | skipped",
      hardware_attestation: "pass | fail | skipped",
      threat_feed: "pass | fail | skipped",
      signature_update_vest: "pass | fail | skipped"
    },
    result: "validated | rejected | pending_review",
    evidence_hash: "SHA-256 hex",
    artifacts: ["string"]
  }
};

module.exports = LogSchema;
