#!/usr/bin/env python3
"""Safely fetch configured rule text and generate client-specific outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from privacy_scan import scan_text
from rulelib import (
    RuleValidationError,
    decode_text,
    load_config,
    render_for_client,
    repository_root,
    validate_text,
)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        raise RuleValidationError(f"redirect refused: {req.full_url} -> {newurl}")


def validate_download_url(url: str, allowed_hosts: set[str]) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise RuleValidationError("remote source must use HTTPS")
    if parsed.hostname not in allowed_hosts:
        raise RuleValidationError(f"download host is not allowed: {parsed.hostname}")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise RuleValidationError("remote source URL contains credentials or a non-HTTPS port")
    if parsed.query or parsed.fragment:
        raise RuleValidationError("remote source URL must not contain query parameters or fragments")
    if not parsed.path.endswith(".list"):
        raise RuleValidationError("remote source URL must identify a .list text file")


def download_text(url: str, allowed_hosts: set[str], maximum_bytes: int) -> bytes:
    validate_download_url(url, allowed_hosts)
    opener = urllib.request.build_opener(NoRedirectHandler())
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "text/plain, application/octet-stream;q=0.9",
            "User-Agent": "Blackyneko-filter-rule-sync/1",
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=20) as response:
            final_url = response.geturl()
            if final_url != url:
                raise RuleValidationError(f"unexpected final URL: {final_url}")
            content_type = response.headers.get_content_type()
            if content_type not in {"text/plain", "application/octet-stream"}:
                raise RuleValidationError(f"unexpected content type: {content_type}")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > maximum_bytes:
                raise RuleValidationError(f"download exceeds {maximum_bytes} bytes")
            data = response.read(maximum_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise RuleValidationError(f"download failed with HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuleValidationError(f"download failed: {exc.reason}") from exc
    if len(data) > maximum_bytes:
        raise RuleValidationError(f"download exceeds {maximum_bytes} bytes")
    return data


def enforce_shrink_limit(
    candidate_rules: int,
    previous_rules: int,
    maximum_shrink_percent: int,
    label: str,
) -> None:
    if previous_rules == 0:
        return
    removed_percent = ((previous_rules - candidate_rules) * 100) / previous_rules
    if removed_percent > maximum_shrink_percent:
        raise RuleValidationError(
            f"{label}: rule count shrank by {removed_percent:.1f}% "
            f"(limit {maximum_shrink_percent}%)"
        )


def _ensure_private(candidate: str, label: str) -> None:
    findings = scan_text(candidate, label)
    if findings:
        raise RuleValidationError("; ".join(findings))


def build_candidates(root: Path, offline: bool) -> tuple[dict[Path, bytes], list[str]]:
    config = load_config(root)
    allowed_hosts = set(config["allowed_download_hosts"])
    candidates: dict[Path, bytes] = {}
    reports: list[str] = []
    lock_sources: dict[str, dict[str, str]] = {}

    for source in config["sources"]:
        input_path = root / source["input"]
        previous_data = input_path.read_bytes()
        previous_text = decode_text(
            previous_data, source["input"], source["maximum_bytes"]
        )
        previous_result = validate_text(previous_text, source["input"], 1)

        if source["mode"] == "remote" and not offline:
            raw_data = download_text(
                source["url"], allowed_hosts, source["maximum_bytes"]
            )
        else:
            raw_data = previous_data

        candidate_text = decode_text(
            raw_data, source["input"], source["maximum_bytes"]
        ).rstrip("\n") + "\n"
        result = validate_text(
            candidate_text, source["input"], source["minimum_rules"]
        )
        enforce_shrink_limit(
            result.rule_count,
            previous_result.rule_count,
            source["maximum_shrink_percent"],
            source["input"],
        )
        _ensure_private(candidate_text, source["input"])

        candidate_data = candidate_text.encode("utf-8")
        candidates[Path(source["input"])] = candidate_data
        digest = hashlib.sha256(candidate_data).hexdigest()
        lock_sources[source["id"]] = {"sha256": digest}
        reports.append(f"{source['input']}: {result.rule_count} rules, sha256={digest}")

        for target in ("loon", "shadowrocket"):
            rendered = render_for_client(candidate_text, source["input"], target)
            _ensure_private(rendered, f"rules/{target}/{source['input']}")
            candidates[Path("rules") / target / source["input"]] = rendered.encode("utf-8")

    lock = {"schema_version": 1, "sources": lock_sources}
    lock_data = (json.dumps(lock, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    candidates[Path("sources.lock.json")] = lock_data
    return candidates, reports


def changed_paths(root: Path, candidates: dict[Path, bytes]) -> list[Path]:
    changed: list[Path] = []
    for relative, data in sorted(candidates.items(), key=lambda item: str(item[0])):
        destination = root / relative
        if not destination.exists() or destination.read_bytes() != data:
            changed.append(relative)
    return changed


def install_transactionally(root: Path, candidates: dict[Path, bytes]) -> list[Path]:
    changed = changed_paths(root, candidates)
    if not changed:
        return []
    backups: dict[Path, bytes | None] = {}
    installed: list[Path] = []
    with tempfile.TemporaryDirectory(prefix=".rule-sync-", dir=root) as temp_name:
        staging = Path(temp_name)
        for relative in changed:
            staged = staging / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(candidates[relative])
        try:
            for relative in changed:
                destination = root / relative
                backups[relative] = destination.read_bytes() if destination.exists() else None
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(staging / relative, destination)
                installed.append(relative)
        except OSError:
            for relative in reversed(installed):
                destination = root / relative
                backup = backups[relative]
                if backup is None:
                    destination.unlink(missing_ok=True)
                else:
                    rollback = staging / (str(relative) + ".rollback")
                    rollback.parent.mkdir(parents=True, exist_ok=True)
                    rollback.write_bytes(backup)
                    os.replace(rollback, destination)
            raise
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=repository_root())
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use current root files instead of downloading remote sources",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate and report changes without writing files",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        candidates, reports = build_candidates(root, args.offline)
        changes = changed_paths(root, candidates)
        if not args.check:
            install_transactionally(root, candidates)
    except (OSError, ValueError, json.JSONDecodeError, RuleValidationError) as exc:
        print(f"sync failed: {exc}", file=sys.stderr)
        return 1
    print("\n".join(reports))
    if changes:
        action = "would update" if args.check else "updated"
        print(f"{action}: " + ", ".join(str(path) for path in changes))
    else:
        print("no changes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
