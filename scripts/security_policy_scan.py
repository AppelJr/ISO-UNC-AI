import json
import sys
from pathlib import Path


def load_policy(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def scan_file(path: Path, patterns: list[str]) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    hits = []
    for pattern in patterns:
        if pattern in text:
            hits.append(pattern)
    return hits


def main() -> int:
    policy_path = sys.argv[1]
    root_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(".")
    policy = load_policy(policy_path)
    protected = policy["protected_paths"]
    patterns = [p for block in policy["forbidden_patterns"] for p in block["patterns"]]
    violations = []
    for protected_dir in protected:
        base = root_path / protected_dir
        if not base.exists():
            continue
        for file_path in base.rglob("*"):
            if file_path.is_file():
                hits = scan_file(file_path, patterns)
                if hits:
                    violations.append(f"{file_path}: {', '.join(hits)}")
    if violations:
        print("ZERO_TOLERANCE_VIOLATIONS")
        for v in violations:
            print(v)
        return 1
    print("ZERO_TOLERANCE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())