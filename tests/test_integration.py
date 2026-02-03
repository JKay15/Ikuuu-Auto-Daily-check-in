import os
import unittest

try:
    import requests  # noqa: F401
except Exception:
    requests = None

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import ikuuuCheckIn as mod


@unittest.skipUnless(os.environ.get("IKUUU_INTEGRATION") == "1", "Integration tests disabled")
class TestIntegration(unittest.TestCase):
    def setUp(self):
        if requests is None:
            self.skipTest("requests not installed")
        self.email = os.environ.get("IKUUU_TEST_EMAIL")
        self.password = os.environ.get("IKUUU_TEST_PASS")
        self.base_url = os.environ.get("IKUUU_TEST_BASE_URL")
        if not self.email or not self.password or not self.base_url:
            self.skipTest("Missing IKUUU_TEST_EMAIL/IKUUU_TEST_PASS/IKUUU_TEST_BASE_URL")

    def test_login_and_checkin_live(self):
        stats = mod.init_stats()
        ok, session, msg, redirect_domain, cred_error = mod.try_login(
            self.base_url, self.email, self.password, stats=stats
        )
        if not ok:
            if cred_error:
                self.fail("Credential error: " + msg)
            self.skipTest("Login not accepted by server: " + msg)

        # Check-in may legitimately fail if already checked in; ensure no exception.
        checkin_domain = redirect_domain or self.base_url
        result = mod.checkin(session, checkin_domain, stats=stats)
        self.assertIn(result, [True, False])

    def test_resolve_and_login_live(self):
        seeds = list(dict.fromkeys([self.base_url] + list(mod.DEFAULT_SEEDS)))
        cfg = {
            "last_success_domain": self.base_url,
            "domains": {},
            "seed_domains": seeds,
            "mail": {"enabled": False},
        }
        stats = mod.init_stats()
        base_url, session = mod.resolve_and_login(self.email, self.password, cfg, stats=stats)
        if not base_url or not session:
            self.skipTest("resolve_and_login could not find a working domain")
        result = mod.checkin(session, base_url, stats=stats)
        self.assertIn(result, [True, False])


if __name__ == "__main__":
    unittest.main()
