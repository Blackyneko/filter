from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from privacy_scan import scan_text


class PrivacyScanTests(unittest.TestCase):
    def test_accepts_github_noreply_email(self):
        self.assertEqual(
            scan_text("Blackyneko <4461548+Blackyneko@users.noreply.github.com>", "log"),
            [],
        )

    def test_rejects_personal_email(self):
        self.assertTrue(scan_text("owner" + "@" + "example.com", "bad"))

    def test_rejects_node_uri(self):
        value = "vmess" + "://" + "abcdefghijklmnopqrstuvwxyz"
        self.assertTrue(scan_text(value, "bad"))

    def test_rejects_token_query(self):
        value = "https://example.com/sub?" + "token=" + "abcdefghijklmno"
        self.assertTrue(scan_text(value, "bad"))

    def test_rejects_private_key(self):
        value = "-----BEGIN " + "PRIVATE KEY-----"
        self.assertTrue(scan_text(value, "bad"))


if __name__ == "__main__":
    unittest.main()
