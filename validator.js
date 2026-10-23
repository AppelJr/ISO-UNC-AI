/**
 * ISO-UNC-AI client-side validator.
 *
 * Client checks are evidence-gated. This module never manufactures a pass.
 * Cryptographic evidence verification remains authoritative in sys-validator.py.
 */

const MODULES = [
  "core_tests",
  "extended_tests",
  "hardware_attestation",
  "threat_feed",
  "signature_update_vest",
];

function requireEvidence(evidence, module) {
  const record = evidence?.[module];
  if (!record || record.status !== "pass" || record.verified !== true) {
    throw new Error(`${module}: verified passing evidence is required`);
  }
  return { module, status: "pass", evidence_id: record.id };
}

const Validator = {
  version: "2.0",

  async runCoreTests(system, evidence) {
    return requireEvidence(evidence, "core_tests");
  },

  async runExtendedTests(system, evidence) {
    return requireEvidence(evidence, "extended_tests");
  },

  async runHardwareAttestation(system, evidence) {
    return requireEvidence(evidence, "hardware_attestation");
  },

  async runThreatFeed(system, evidence) {
    return requireEvidence(evidence, "threat_feed");
  },

  async runSignatureUpdateVest(system, evidence) {
    return requireEvidence(evidence, "signature_update_vest");
  },

  async validate(system, evidence) {
    const modules = [];
    const runners = [
      this.runCoreTests.bind(this),
      this.runExtendedTests.bind(this),
      this.runHardwareAttestation.bind(this),
      this.runThreatFeed.bind(this),
      this.runSignatureUpdateVest.bind(this),
    ];

    try {
      for (const run of runners) {
        modules.push(await run(system, evidence));
      }
      if (modules.length !== MODULES.length) throw new Error("required module count mismatch");
      return {
        result: "validated",
        modules,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      return {
        result: "rejected",
        modules,
        reason: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      };
    }
  },
};

if (typeof module !== "undefined") module.exports = Validator;
