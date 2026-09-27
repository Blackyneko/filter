#!/usr/bin/env python3
"""Scan repository text for proxy subscriptions, credentials and personal email."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from rulelib import repository_root


TEXT_SUFFIXES = {"", ".json", ".list", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"}

PATTERNS = {
    "proxy node URI": re.compile(
        r"(?i)\b(?:ss|ssr|vmess|vless|trojan|tuic|hysteria2?|wireguard)://[A-Za-z0-9_+/%=-]{8,}"
    ),
    "private key": re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "authorization credential": re.compile(r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/-]{8,}"),
    "cookie value": re.compile(r"(?i)\bCookie\s*:\s*[^\s;=]{1,64}=[^\s;]{6,}"),
    "credential query parameter": re.compile(
        r"(?i)[?&](?:access_?token|api_?key|auth|key|password|secret|token)=[^&#\s]{6,}"
    ),
    "known API key": re.compile(
        r"(?:sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,}|gh[pousr]_[A-Za-z0-9]{30,})"
    ),
}

EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})(?![\w.-])", re.I)


def scan_text(text: str, label: str) -> list[str]:
    findings: list[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for name, pattern in PATTERNS.items():
            if pattern.search(line):
                findings.append(f"{label}:{line_number}: {name}")
        for match in EMAIL_RE.finditer(line):
            email = match.group(1).lower()
            if not email.endswith("@users.noreply.github.com") and email != "noreply@github.com":
                findings.append(f"{label}:{line_number}: personal email")
    return findings


def iter_text_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        yield path


def scan_repository(root: Path) -> list[str]:
    findings: list[str] = []
    for path in iter_text_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(f"{path.relative_to(root)}: non-UTF-8 text")
            continue
        findings.extend(scan_text(text, str(path.relative_to(root))))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=repository_root())
    args = parser.parse_args()
    findings = scan_repository(args.root.resolve())
    if findings:
        print("privacy scan failed:", file=sys.stderr)
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("privacy scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

