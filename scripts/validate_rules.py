#!/usr/bin/env python3
"""Validate configured source files and generated client outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from rulelib import RuleValidationError, decode_text, load_config, repository_root, validate_text


def validate_repository(root: Path, verify_lock: bool = True) -> list[str]:
    config = load_config(root)
    lock_path = root / "sources.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.exists() else {}
    lock_sources = lock.get("sources", {})
    reports: list[str] = []

    for source in config["sources"]:
        input_path = root / source["input"]
        data = input_path.read_bytes()
        text = decode_text(data, source["input"], source["maximum_bytes"])
        result = validate_text(text, source["input"], source["minimum_rules"])
        digest = hashlib.sha256(data).hexdigest()
        if verify_lock and lock_sources.get(source["id"], {}).get("sha256") != digest:
            raise RuleValidationError(
                f"{source['input']}: SHA-256 does not match sources.lock.json"
            )
        reports.append(f"{source['input']}: {result.rule_count} rules, sha256={digest}")

        for target in ("loon", "shadowrocket"):
            output = root / "rules" / target / source["input"]
            if output.exists():
                output_text = decode_text(
                    output.read_bytes(), str(output.relative_to(root)), source["maximum_bytes"]
                )
                output_result = validate_text(
                    output_text, str(output.relative_to(root)), source["minimum_rules"], target
                )
                reports.append(
                    f"{output.relative_to(root)}: {output_result.rule_count} rules"
                )
    return reports


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=repository_root())
    parser.add_argument("--no-lock", action="store_true", help="skip lock hash verification")
    args = parser.parse_args()
    try:
        reports = validate_repository(args.root.resolve(), not args.no_lock)
    except (OSError, json.JSONDecodeError, RuleValidationError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1
    print("\n".join(reports))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

