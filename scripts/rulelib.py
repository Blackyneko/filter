#!/usr/bin/env python3
"""Shared validation helpers for rule files."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


COMMON_TYPES = {
    "AND",
    "DOMAIN",
    "DOMAIN-KEYWORD",
    "DOMAIN-SUFFIX",
    "IP-CIDR",
    "IP-CIDR6",
    "NOT",
    "OR",
}

CLIENT_TYPES = {
    "loon": COMMON_TYPES,
    "shadowrocket": COMMON_TYPES,
}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)


class RuleValidationError(ValueError):
    """Raised when a source is unsafe or syntactically invalid."""


@dataclass(frozen=True)
class ValidationResult:
    path: str
    rule_count: int
    sha256: str


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_config(root: Path | None = None) -> dict:
    root = root or repository_root()
    config = json.loads((root / "sources.json").read_text(encoding="utf-8"))
    if config.get("schema_version") != 1:
        raise RuleValidationError("sources.json: unsupported schema_version")
    hosts = config.get("allowed_download_hosts")
    sources = config.get("sources")
    if not isinstance(hosts, list) or not hosts or not all(isinstance(x, str) for x in hosts):
        raise RuleValidationError("sources.json: allowed_download_hosts must be a non-empty list")
    if not isinstance(sources, list) or not sources:
        raise RuleValidationError("sources.json: sources must be a non-empty list")

    seen_ids: set[str] = set()
    seen_inputs: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            raise RuleValidationError("sources.json: each source must be an object")
        source_id = source.get("id")
        input_name = source.get("input")
        mode = source.get("mode")
        if not isinstance(source_id, str) or not re.fullmatch(r"[a-z0-9-]+", source_id):
            raise RuleValidationError("sources.json: invalid source id")
        if source_id in seen_ids:
            raise RuleValidationError(f"sources.json: duplicate source id {source_id}")
        seen_ids.add(source_id)
        if not isinstance(input_name, str) or Path(input_name).name != input_name:
            raise RuleValidationError(f"sources.json: unsafe input path for {source_id}")
        if not input_name.endswith(".list") or input_name in seen_inputs:
            raise RuleValidationError(f"sources.json: invalid or duplicate input for {source_id}")
        seen_inputs.add(input_name)
        if mode not in {"local", "remote"}:
            raise RuleValidationError(f"sources.json: invalid mode for {source_id}")
        if mode == "remote" and not isinstance(source.get("url"), str):
            raise RuleValidationError(f"sources.json: remote source {source_id} needs a url")
        for key in ("minimum_rules", "maximum_bytes"):
            if not isinstance(source.get(key), int) or source[key] <= 0:
                raise RuleValidationError(f"sources.json: {key} must be positive for {source_id}")
        shrink = source.get("maximum_shrink_percent")
        if not isinstance(shrink, int) or not 0 <= shrink < 100:
            raise RuleValidationError(
                f"sources.json: maximum_shrink_percent must be 0..99 for {source_id}"
            )
    return config


def decode_text(data: bytes, label: str, maximum_bytes: int) -> str:
    if len(data) > maximum_bytes:
        raise RuleValidationError(f"{label}: exceeds {maximum_bytes} bytes")
    if b"\x00" in data:
        raise RuleValidationError(f"{label}: contains NUL bytes")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RuleValidationError(f"{label}: must be UTF-8 text") from exc
    lowered = text[:4096].lower()
    if "<!doctype html" in lowered or "<html" in lowered or "<body" in lowered:
        raise RuleValidationError(f"{label}: looks like an HTML error page")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def iter_rule_lines(text: str) -> Iterable[tuple[int, str]]:
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        yield number, line


def _validate_logic(line: str, label: str, number: int) -> None:
    if line.count("(") != line.count(")") or "((" not in line or "))" not in line:
        raise RuleValidationError(f"{label}:{number}: malformed logical rule")
    nested_types = re.findall(r"\(\s*([A-Z][A-Z0-9-]*)\s*,", line)
    if not nested_types:
        raise RuleValidationError(f"{label}:{number}: logical rule has no nested rules")
    invalid = sorted(set(nested_types) - COMMON_TYPES)
    if invalid:
        raise RuleValidationError(
            f"{label}:{number}: unsupported nested rule type {', '.join(invalid)}"
        )


def _validate_simple(parts: list[str], label: str, number: int) -> None:
    rule_type, value = parts[0], parts[1]
    if not value:
        raise RuleValidationError(f"{label}:{number}: empty rule value")
    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"} and not DOMAIN_RE.fullmatch(value):
        raise RuleValidationError(f"{label}:{number}: invalid domain {value!r}")
    if rule_type == "DOMAIN-KEYWORD" and any(char.isspace() for char in value):
        raise RuleValidationError(f"{label}:{number}: invalid domain keyword")
    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RuleValidationError(f"{label}:{number}: invalid CIDR {value!r}") from exc
        if rule_type == "IP-CIDR" and network.version != 4:
            raise RuleValidationError(f"{label}:{number}: IP-CIDR must contain IPv4")
        if rule_type == "IP-CIDR6" and network.version != 6:
            raise RuleValidationError(f"{label}:{number}: IP-CIDR6 must contain IPv6")


def validate_text(
    text: str,
    label: str,
    minimum_rules: int = 1,
    target: str | None = None,
) -> ValidationResult:
    if target is not None and target not in CLIENT_TYPES:
        raise RuleValidationError(f"unknown client target {target}")
    allowed_types = CLIENT_TYPES[target] if target else COMMON_TYPES
    count = 0
    for number, line in iter_rule_lines(text):
        if line.startswith("[") or "=" in line.split(",", 1)[0]:
            raise RuleValidationError(f"{label}:{number}: full configurations are not rule lists")
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 2:
            raise RuleValidationError(f"{label}:{number}: rule needs a type and value")
        rule_type = parts[0]
        if rule_type not in allowed_types:
            raise RuleValidationError(f"{label}:{number}: unsupported rule type {rule_type!r}")
        if rule_type in {"AND", "OR", "NOT"}:
            _validate_logic(line, label, number)
        else:
            _validate_simple(parts, label, number)
        count += 1
    if count < minimum_rules:
        raise RuleValidationError(f"{label}: only {count} rules; minimum is {minimum_rules}")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return ValidationResult(label, count, digest)


def render_for_client(text: str, source_name: str, target: str) -> str:
    client_name = "Loon" if target == "loon" else "Shadowrocket"
    body = text.rstrip("\n") + "\n"
    rendered = (
        f"# Generated from {source_name} for {client_name}; do not edit this copy.\n"
        "# Attribution and license: https://github.com/Blackyneko/filter/blob/main/SOURCES.md\n"
        f"{body}"
    )
    validate_text(rendered, f"rules/{target}/{source_name}", target=target)
    return rendered

