from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from rulelib import RuleValidationError
from sync_rules import enforce_shrink_limit, validate_download_url


class SyncSafetyTests(unittest.TestCase):
    def test_accepts_fixed_https_list(self):
        validate_download_url(
            "https://raw.githubusercontent.com/owner/repo/main/file.list",
            {"raw.githubusercontent.com"},
        )

    def test_rejects_unlisted_host(self):
        with self.assertRaisesRegex(RuleValidationError, "not allowed"):
            validate_download_url("https://example.com/file.list", {"raw.githubusercontent.com"})

    def test_rejects_query_credentials(self):
        with self.assertRaisesRegex(RuleValidationError, "query"):
            validate_download_url(
                "https://raw.githubusercontent.com/owner/repo/main/file.list?"
                + "token="
                + "secret-value",
                {"raw.githubusercontent.com"},
            )

    def test_rejects_abnormal_shrink(self):
        with self.assertRaisesRegex(RuleValidationError, "shrank"):
            enforce_shrink_limit(70, 100, 20, "example.list")

    def test_accepts_shrink_at_limit(self):
        enforce_shrink_limit(80, 100, 20, "example.list")


if __name__ == "__main__":
    unittest.main()
