"""Read-only SHA-256 verification for the Stage 12 freeze manifest."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "research_release/FREEZE_MANIFEST.json").read_text())


def main() -> int:
    failures = []
    checked = 0
    for group in MANIFEST["sha256"].values():
        for relative, expected in group.items():
            path = ROOT / relative
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            checked += 1
            if actual != expected:
                failures.append((relative, expected, actual))
    if failures:
        for relative, expected, actual in failures:
            print(f"MISMATCH {relative}\n  expected {expected}\n  actual   {actual}")
        return 1
    print(f"Freeze verification: MATCH ({checked} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
