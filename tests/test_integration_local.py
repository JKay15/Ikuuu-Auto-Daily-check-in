import json
import os
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

try:
    import requests  # noqa: F401
except Exception:
    requests = None

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import ikuuuCheckIn as mod


class ScenarioHandler(BaseHTTPRequestHandler):
    scenario = {
        "login": "success",
        "checkin": "success",
        "html": "",
        "delay": 0,
        "last_login_body": None,
    }

    def log_message(self, *_args):
        return

    def _write_json(self, status, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _write_text(self, status, text, content_type="text/html"):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        delay = self.scenario.get("delay", 0)
        if delay:
            time.sleep(delay)
        if self.path in ("/", "/auth/login"):
            html = self.scenario.get("html", "")
            self._write_text(200, html)
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/auth/login2")
            self.end_headers()
            return
        if self.path == "/auth/login2":
            self._write_json(200, {"ret": 1, "msg": "ok"})
            return
        self._write_text(404, "not found")

    def do_POST(self):
        delay = self.scenario.get("delay", 0)
        if delay:
            time.sleep(delay)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        params = parse_qs(body)
        self.scenario["last_login_body"] = params

        if self.path == "/auth/login":
            mode = self.scenario.get("login", "success")
            if mode == "success":
                self._write_json(200, {"ret": 1, "msg": "ok"})
            elif mode == "redirect":
                self.send_response(302)
                self.send_header("Location", "/auth/login2")
                self.end_headers()
            elif mode == "cred_error":
                self._write_json(200, {"ret": 0, "msg": "密码错误"})
            elif mode == "csrf_required":
                token = params.get("_token", [""])[0]
                if token == "csrf123":
                    self._write_json(200, {"ret": 1, "msg": "ok"})
                else:
                    self._write_json(200, {"ret": 0, "msg": "token错误"})
            elif mode == "other_error":
                self._write_json(200, {"ret": 0, "msg": "系统错误"})
            elif mode == "non_json":
                self._write_text(200, "<html>not json</html>")
            elif mode == "server_error":
                self._write_text(500, "error")
            else:
                self._write_json(200, {"ret": 0, "msg": "unknown"})
            return

        if self.path == "/user/checkin":
            mode = self.scenario.get("checkin", "success")
            if mode == "success":
                self._write_json(200, {"ret": 1, "msg": "ok"})
            elif mode == "fail":
                self._write_json(200, {"ret": 0, "msg": "already"})
            elif mode == "non_json":
                self._write_text(200, "<html>not json</html>")
            else:
                self._write_text(500, "error")
            return

        self._write_text(404, "not found")


class LocalServer:
    def __init__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ScenarioHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@unittest.skipUnless(requests is not None, "requests not installed")
class TestLocalIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.server = LocalServer()
            cls.server.start()
            cls.base_url = f"http://127.0.0.1:{cls.server.port}"
        except PermissionError as exc:
            raise unittest.SkipTest(f"Local server not permitted: {exc}")

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        ScenarioHandler.scenario.update(
            {
                "login": "success",
                "checkin": "success",
                "html": "",
                "delay": 0,
                "last_login_body": None,
            }
        )

    def test_login_success_and_checkin_success(self):
        stats = mod.init_stats()
        ok, session, msg, _redirect, cred = mod.try_login(
            self.base_url, "a@b.com", "pw", stats=stats
        )
        self.assertTrue(ok)
        self.assertFalse(cred)
        self.assertEqual(msg, "登录成功")
        self.assertEqual(stats["login_success"], 1)
        params = ScenarioHandler.scenario.get("last_login_body") or {}
        self.assertIn("email", params)
        self.assertIn("password", params)
        self.assertIn("host", params)
        self.assertIn("pageLoadedAt", params)

        result = mod.checkin(session, self.base_url, stats=stats)
        self.assertTrue(result)
        self.assertEqual(stats["checkin_success"], 1)

    def test_login_cred_error(self):
        ScenarioHandler.scenario["login"] = "cred_error"
        ok, _session, _msg, _redirect, cred = mod.try_login(
            self.base_url, "a", "b"
        )
        self.assertFalse(ok)
        self.assertTrue(cred)

    def test_login_other_error(self):
        ScenarioHandler.scenario["login"] = "other_error"
        ok, _session, msg, _redirect, cred = mod.try_login(
            self.base_url, "a", "b"
        )
        self.assertFalse(ok)
        self.assertFalse(cred)
        self.assertIn("系统错误", msg)

    def test_login_non_json(self):
        ScenarioHandler.scenario["login"] = "non_json"
        ok, _session, msg, _redirect, _cred = mod.try_login(
            self.base_url, "a", "b"
        )
        self.assertFalse(ok)
        self.assertEqual(msg, "登录响应非JSON")

    def test_login_csrf_required(self):
        ScenarioHandler.scenario["login"] = "csrf_required"
        ScenarioHandler.scenario["html"] = '<input type="hidden" name="_token" value="csrf123">'
        ok, _session, msg, _redirect, _cred = mod.try_login(
            self.base_url, "a", "b"
        )
        self.assertTrue(ok, msg)

    def test_login_captcha_detected(self):
        ScenarioHandler.scenario["login"] = "success"
        ScenarioHandler.scenario["html"] = "please complete captcha"
        ok, _session, msg, _redirect, _cred = mod.try_login(
            self.base_url, "a", "b"
        )
        self.assertFalse(ok)
        self.assertIn("验证码", msg)

    def test_checkin_non_json(self):
        ScenarioHandler.scenario["login"] = "success"
        ScenarioHandler.scenario["checkin"] = "non_json"
        ok, session, _msg, _redirect, _cred = mod.try_login(
            self.base_url, "a", "b"
        )
        self.assertTrue(ok)
        result = mod.checkin(session, self.base_url)
        self.assertFalse(result)

    @mock.patch("ikuuuCheckIn.notify_macos", return_value=None)
    def test_discover_from_html(self, _notify):
        ScenarioHandler.scenario["html"] = "see https://ikuuu.nl and https://ikuuu.fyi"
        found = mod.discover_from_html(self.base_url)
        self.assertIn("https://ikuuu.nl", found)
        self.assertIn("https://ikuuu.fyi", found)

    def test_redirect_handling(self):
        ScenarioHandler.scenario["login"] = "redirect"
        ok, session, _msg, redirect_domain, _cred = mod.try_login(self.base_url, "a", "b")
        self.assertTrue(ok)
        self.assertEqual(redirect_domain, self.base_url)
        self.assertIsNotNone(session)


if __name__ == "__main__":
    unittest.main()
