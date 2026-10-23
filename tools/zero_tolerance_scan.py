#!/usr/bin/env python3
"""Enforce the repository zero-tolerance policy against placeholder security code."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path

POLICY = Path("ZERO_TOLERANCE_POLICY.json")
SKIP = {".git", ".venv", "__pycache__", "node_modules"}
TEXT_SUFFIXES = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".md", ".sh", ".html"}


def main() -> int:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    findings: list[str] = []
    for rule in policy.get("forbidden_patterns", []):
        category = rule["category"]
        patterns = rule.get("patterns", [])
        for path in Path(".").rglob("*"):
            if not path.is_file() or path.suffix not in TEXT_SUFFIXES:
                continue
            if any(part in SKIP for part in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for pattern in patterns:
                if pattern in text:
                    findings.append(f"{category}: {path}: {pattern}")
    if findings:
        print("ZERO-TOLERANCE SCAN: FAIL")
        print("\n".join(sorted(set(findings))))
        return 1
    print("ZERO-TOLERANCE SCAN: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
