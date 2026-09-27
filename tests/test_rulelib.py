from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from rulelib import RuleValidationError, decode_text, render_for_client, validate_text


class RuleValidationTests(unittest.TestCase):
    def test_accepts_supported_rules(self):
        text = (
            "# example\n"
            "DOMAIN,example.com\n"
            "DOMAIN-SUFFIX,example.org\n"
            "IP-CIDR,192.0.2.0/24,no-resolve\n"
            "IP-CIDR6,2001:db8::/32,no-resolve\n"
            "AND,((DOMAIN-KEYWORD,api),(DOMAIN-SUFFIX,example.net))\n"
        )
        result = validate_text(text, "example.list", minimum_rules=5, target="loon")
        self.assertEqual(result.rule_count, 5)

    def test_rejects_html_error_page(self):
        with self.assertRaisesRegex(RuleValidationError, "HTML"):
            decode_text(b"<!doctype html><title>404</title>", "bad.list", 1024)

    def test_rejects_invalid_rule_type(self):
        with self.assertRaisesRegex(RuleValidationError, "unsupported rule type"):
            validate_text("SCRIPT,evil.js\n", "bad.list")

    def test_rejects_invalid_cidr(self):
        with self.assertRaisesRegex(RuleValidationError, "invalid CIDR"):
            validate_text("IP-CIDR,999.1.1.1/24\n", "bad.list")

    def test_renders_client_specific_header(self):
        output = render_for_client("DOMAIN,example.com\n", "Example.list", "shadowrocket")
        self.assertIn("for Shadowrocket", output)
        self.assertIn("DOMAIN,example.com", output)


if __name__ == "__main__":
    unittest.main()
