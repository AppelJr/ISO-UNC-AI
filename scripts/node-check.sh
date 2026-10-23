#!/usr/bin/env bash
set -Eeuo pipefail

# Run the repository's validator help check. Dependency installation is intentionally
# not performed here; this script is an explicit validation command only.
node src/js/validator.js --help
