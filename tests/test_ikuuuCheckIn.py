import base64
import datetime
import email
import itertools
import os
import tempfile
import unittest
from unittest import mock

import sys

# Provide a stub requests module if dependency isn't installed in the test env.
try:
    import requests  # noqa: F401
except Exception:
    import types

    sys.modules["requests"] = types.SimpleNamespace(get=None, session=None)

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import ikuuuCheckIn as mod


class DummyResp:
    def __init__(self, url="", text="", json_data=None, json_exc=None, status_code=200):
        self.url = url
        self.text = text
        self._json_data = json_data
        self._json_exc = json_exc
        self.status_code = status_code

    def json(self):
        if self._json_exc:
            raise self._json_exc
        return self._json_data


class DummySession:
    def __init__(self, post_resp, get_resp=None):
        self._post_resp = post_resp
        self._get_resp = get_resp
        self.last_post_url = None

    def post(self, *args, **kwargs):
        if args:
            self.last_post_url = args[0]
        return self._post_resp

    def get(self, *args, **kwargs):
        if self._get_resp is None:
            raise RuntimeError("no get response")
        return self._get_resp


class DummySMTP:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.started = False
        self.logged_in = False
        self.sent = []

    def starttls(self):
        self.started = True

    def login(self, user, password):
        self.logged_in = True
        self.user = user
        self.password = password

    def sendmail(self, from_addr, to_addrs, msg):
        self.sent.append((from_addr, to_addrs, msg))

    def quit(self):
        return True


class DummyIMAP:
    def __init__(self, host):
        self.host = host
        self._emails = []

    def login(self, user, password):
        return "OK", []

    def select(self, folder):
        return "OK", []

    def search(self, *args):
        # return two ids
        return "OK", [b"1 2"]

    def fetch(self, msg_id, _):
        idx = 0 if msg_id == b"1" else 1
        raw = self._emails[idx]
        return "OK", [(None, raw)]

    def logout(self):
        return "OK", []


class TestIkuuuCheckIn(unittest.TestCase):
    def test_normalize_domain(self):
        self.assertIsNone(mod.normalize_domain(None))
        self.assertIsNone(mod.normalize_domain("   "))
        self.assertEqual(mod.normalize_domain("ikuuu.nl"), "https://ikuuu.nl")
        self.assertEqual(mod.normalize_domain("http://IKUUU.NL/abc"), "http://ikuuu.nl")
        self.assertEqual(mod.normalize_domain("https://ikuuu.nl."), "https://ikuuu.nl")

    def test_extract_domains_from_text(self):
        text = "See https://ikuuu.nl/path and ikuuu.fyi plus https://example.com"
        result = set(mod.extract_domains_from_text(text))
        self.assertEqual(result, {"https://ikuuu.nl", "https://ikuuu.fyi"})

    def test_extract_domains_from_scripts_concat(self):
        html = "const a='ikuuu'+'.nl'; const b=\"https://ikuuu.f\"+\"yi\";"
        result = set(mod.extract_domains_from_scripts(html))
        self.assertEqual(result, {"https://ikuuu.nl", "https://ikuuu.fyi"})

    def test_extract_origin_body(self):
        html = '<script>var originBody = "PGgxPkhlbGxvPC9oMT4=";</script>'
        decoded = mod.extract_origin_body(html)
        self.assertIn("<h1>Hello</h1>", decoded)

    def test_extract_geetest_params(self):
        html = "initGeetest4({captchaId:'abc123def4567890', riskType: 'slide'})"
        cid, params = mod.extract_geetest_params(html)
        self.assertEqual(cid, "abc123def4567890")
        self.assertEqual(params["riskType"], "slide")

    def test_extract_hidden_inputs(self):
        html = '<input type="hidden" name="token" value="abc"><input type="hidden" name="_token" value="xyz">'
        tokens = mod.extract_hidden_inputs(html)
        self.assertEqual(tokens["token"], "abc")
        self.assertEqual(tokens["_token"], "xyz")

    def test_extract_csrf_token(self):
        html = '<meta name="csrf-token" content="hello">'
        self.assertEqual(mod.extract_csrf_token(html), "hello")

    def test_detect_captcha(self):
        self.assertTrue(mod.detect_captcha("need CAPTCHA now"))
        self.assertTrue(mod.detect_captcha("需要验证码"))
        self.assertFalse(mod.detect_captcha("normal page"))

    def test_get_candidates_order(self):
        cfg = {
            "last_success_domain": "https://ikuuu.fyi",
            "domain_ordering": {"mode": "success_rate"},
            "domains": {
                "https://ikuuu.nl": {
                    "success_count": 1,
                    "fail_count": 0,
                    "last_success": "2026-02-01",
                },
                "https://ikuuu.one": {
                    "success_count": 2,
                    "fail_count": 0,
                    "last_success": "2025-01-01",
                },
            },
            "seed_domains": ["https://ikuuu.nl", "https://ikuuu.de"],
        }
        candidates = mod.get_candidates(cfg)
        self.assertEqual(candidates[0], "https://ikuuu.fyi")
        self.assertEqual(candidates[1], "https://ikuuu.nl")
        self.assertIn("https://ikuuu.one", candidates)
        self.assertIn("https://ikuuu.de", candidates)

    @mock.patch("ikuuuCheckIn.requests.get")
    def test_discover_from_html(self, mock_get):
        obfuscated = "const a='ikuuu'+'.nl'; const b=\"https://ikuuu.f\"+\"yi\";"
        mock_get.side_effect = [
            DummyResp(url="https://ikuuu.de/home", text="go https://ikuuu.fyi"),
            DummyResp(url="https://ikuuu.de/auth/login", text=obfuscated),
        ]
        found = set(mod.discover_from_html("https://ikuuu.de"))
        self.assertEqual(found, {"https://ikuuu.fyi", "https://ikuuu.nl"})

    @mock.patch("ikuuuCheckIn.requests.get")
    def test_discover_from_html_origin_body(self, mock_get):
        origin = "<a href='https://ikuuu.fyi'>link</a>"
        encoded = base64.b64encode(origin.encode("utf-8")).decode("ascii")
        html = f'<script>var originBody = \"{encoded}\";</script>'
        mock_get.side_effect = [
            DummyResp(url="https://ikuuu.nl/home", text=html),
            DummyResp(url="https://ikuuu.nl/auth/login", text=""),
        ]
        found = set(mod.discover_from_html("https://ikuuu.nl"))
        self.assertIn("https://ikuuu.fyi", found)

    @mock.patch("ikuuuCheckIn.notify_macos")
    def test_send_probe_email_requires_confirm(self, mock_notify):
        cfg = {"mail": {"enabled": True, "confirm_before_send": True, "confirmed": False}}
        result = mod.send_probe_email(cfg)
        self.assertFalse(result)
        self.assertTrue(cfg["mail"]["pending_send"])
        self.assertTrue(cfg["mail"]["last_mail_attempt"])
        mock_notify.assert_called_once()

    @mock.patch("ikuuuCheckIn.get_mail_password", return_value="pw")
    @mock.patch("ikuuuCheckIn.smtplib.SMTP", side_effect=DummySMTP)
    def test_send_probe_email_success(self, _smtp, _pw):
        cfg = {
            "mail": {
                "enabled": True,
                "confirm_before_send": True,
                "confirmed": True,
                "smtp_user": "u",
                "from_addr": "u",
                "to_addr": "t",
            }
        }
        result = mod.send_probe_email(cfg)
        self.assertTrue(result)
        self.assertTrue(cfg["mail"]["last_mail_sent"])
        self.assertFalse(cfg["mail"]["pending_send"])
        self.assertFalse(cfg["mail"]["confirmed"])

    @mock.patch("ikuuuCheckIn.get_mail_password", return_value="pw")
    @mock.patch("ikuuuCheckIn.imaplib.IMAP4_SSL")
    def test_fetch_domains_from_email(self, mock_imap, _pw):
        msg1 = email.message.EmailMessage()
        msg1.set_content("new domain https://ikuuu.nl")
        msg2 = email.message.EmailMessage()
        msg2.set_content("backup ikuuu.fyi")

        dummy = DummyIMAP("imap")
        dummy._emails = [msg1.as_bytes(), msg2.as_bytes()]
        mock_imap.return_value = dummy

        cfg = {"mail": {"enabled": True, "imap_user": "u", "imap_host": "imap", "to_addr": "find@ikuuu.pro"}}
        result = set(mod.fetch_domains_from_email(cfg, datetime.datetime.now()))
        self.assertEqual(result, {"https://ikuuu.nl", "https://ikuuu.fyi"})

    def test_extract_message_text_multipart(self):
        msg = email.message.EmailMessage()
        msg.set_content("plain text")
        msg.add_alternative("<p>html text</p>", subtype="html")
        text = mod.extract_message_text(msg)
        self.assertIn("plain text", text)
        self.assertIn("html text", text)

    @mock.patch("ikuuuCheckIn.requests.session")
    def test_try_login_success_and_redirect(self, mock_session):
        resp = DummyResp(
            url="https://ikuuu.fyi/auth/login",
            text="ok",
            json_data={"ret": 1},
        )
        mock_session.return_value = DummySession(resp, get_resp=DummyResp(text=""))
        ok, session, msg, redirect_domain, cred_error = mod.try_login("https://ikuuu.nl", "a", "b")
        self.assertTrue(ok)
        self.assertIsNotNone(session)
        self.assertEqual(msg, "登录成功")
        self.assertEqual(redirect_domain, "https://ikuuu.fyi")
        self.assertFalse(cred_error)

    @mock.patch("ikuuuCheckIn.requests.session")
    def test_try_login_cred_error(self, mock_session):
        resp = DummyResp(
            url="https://ikuuu.nl/auth/login",
            text="bad",
            json_data={"ret": 0, "msg": "密码错误"},
        )
        mock_session.return_value = DummySession(resp, get_resp=DummyResp(text=""))
        ok, session, msg, redirect_domain, cred_error = mod.try_login("https://ikuuu.nl", "a", "b")
        self.assertFalse(ok)
        self.assertTrue(cred_error)

    @mock.patch("ikuuuCheckIn.solve_geetest_v4", return_value=({"lot_number": "1"}, None))
    @mock.patch("ikuuuCheckIn.requests.session")
    def test_try_login_with_captcha_solver(self, mock_session, _solver):
        html = "initGeetest4({captchaId:'abc123def4567890'})"
        get_resp = DummyResp(text=html)
        post_resp = DummyResp(url="https://ikuuu.nl/auth/login", text="ok", json_data={"ret": 1})
        mock_session.return_value = DummySession(post_resp, get_resp=get_resp)
        ok, session, msg, _redirect, _cred = mod.try_login(
            "https://ikuuu.nl", "a", "b", login_opts={"captcha_solver": {"enabled": True}}
        )
        self.assertTrue(ok)

    @mock.patch("ikuuuCheckIn.requests.session")
    def test_try_login_login_page_redirect_updates_post_url(self, mock_session):
        get_resp = DummyResp(url="https://ikuuu.fyi/auth/login", text="")
        post_resp = DummyResp(url="https://ikuuu.fyi/auth/login", text="ok", json_data={"ret": 1})
        dummy_session = DummySession(post_resp, get_resp=get_resp)
        mock_session.return_value = dummy_session
        ok, _session, _msg, _redirect, _cred = mod.try_login("https://ikuuu.nl", "a", "b")
        self.assertTrue(ok)
        self.assertEqual(dummy_session.last_post_url, "https://ikuuu.fyi/auth/login")

    @mock.patch("ikuuuCheckIn.try_login")
    def test_resolve_and_login_success_first(self, mock_try_login):
        cfg = {"last_success_domain": "https://ikuuu.fyi", "domains": {}, "seed_domains": []}
        mock_try_login.return_value = (True, "session", "ok", None, False)
        base_url, session = mod.resolve_and_login("a", "b", cfg)
        self.assertEqual(base_url, "https://ikuuu.fyi")
        self.assertEqual(session, "session")
        self.assertEqual(cfg["last_success_domain"], "https://ikuuu.fyi")

    @mock.patch("ikuuuCheckIn.discover_from_html", return_value=["https://ikuuu.new"])
    @mock.patch("ikuuuCheckIn.try_login")
    def test_resolve_and_login_html_discovery(self, mock_try_login, mock_discover):
        cfg = {"last_success_domain": "https://ikuuu.fail", "domains": {}, "seed_domains": []}

        def side_effect(base_url, *_, **__):
            if base_url == "https://ikuuu.new":
                return True, "session", "ok", None, False
            return False, None, "fail", None, False

        mock_try_login.side_effect = side_effect
        base_url, session = mod.resolve_and_login("a", "b", cfg)
        self.assertEqual(base_url, "https://ikuuu.new")
        self.assertEqual(session, "session")
        self.assertTrue(mock_discover.called)

    @mock.patch("ikuuuCheckIn.try_login")
    def test_resolve_and_login_redirect_returns_success_domain(self, mock_try_login):
        cfg = {"last_success_domain": "https://ikuuu.fyi", "domains": {}, "seed_domains": []}
        mock_try_login.return_value = (True, "session", "ok", "https://ikuuu.nl", False)
        base_url, session = mod.resolve_and_login("a", "b", cfg)
        self.assertEqual(base_url, "https://ikuuu.nl")
        self.assertEqual(session, "session")
        self.assertEqual(cfg["last_success_domain"], "https://ikuuu.nl")

    @mock.patch("ikuuuCheckIn.fetch_domains_from_email", return_value=["https://ikuuu.new"])
    @mock.patch("ikuuuCheckIn.send_probe_email", return_value=True)
    @mock.patch("ikuuuCheckIn.discover_from_html", return_value=[])
    @mock.patch("ikuuuCheckIn.try_login")
    def test_resolve_and_login_email_fallback(self, mock_try, _discover, _send, _fetch):
        cfg = {
            "last_success_domain": "https://ikuuu.fail",
            "domains": {},
            "seed_domains": [],
            "mail": {"enabled": True, "poll_seconds": 1, "poll_interval": 1},
        }

        def side_effect(base_url, *_, **__):
            if base_url == "https://ikuuu.new":
                return True, "session", "ok", None, False
            return False, None, "fail", None, False

        mock_try.side_effect = side_effect

        time_seq = itertools.chain([0, 0, 10])
        with mock.patch("ikuuuCheckIn.time.time", side_effect=lambda: next(time_seq)):
            with mock.patch("ikuuuCheckIn.time.sleep", return_value=None):
                base_url, session = mod.resolve_and_login("a", "b", cfg)

        self.assertEqual(base_url, "https://ikuuu.new")
        self.assertEqual(session, "session")

    @mock.patch("ikuuuCheckIn.send_probe_email")
    @mock.patch("ikuuuCheckIn.try_login")
    def test_resolve_and_login_cred_error_stops(self, mock_try, mock_send):
        cfg = {"last_success_domain": "https://ikuuu.fail", "domains": {}, "seed_domains": []}
        mock_try.return_value = (False, None, "密码错误", None, True)
        base_url, session = mod.resolve_and_login("a", "b", cfg)
        self.assertIsNone(base_url)
        self.assertIsNone(session)
        mock_send.assert_not_called()

    def test_load_and_save_config_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.json")
            original = mod.CONFIG_PATH
            try:
                mod.CONFIG_PATH = path
                cfg = mod.load_config()
                cfg["last_success_domain"] = "https://ikuuu.nl"
                mod.save_config(cfg)
                loaded = mod.load_config()
                self.assertEqual(loaded["last_success_domain"], "https://ikuuu.nl")
            finally:
                mod.CONFIG_PATH = original

    def test_load_accounts_from_env_json(self):
        env = '[{\"name\":\"a\",\"email\":\"e@example.com\",\"passwd\":\"p\"}]'
        with mock.patch.dict(os.environ, {"IKUUU_ACCOUNTS": env}, clear=False):
            accounts = mod.load_accounts({})
        self.assertEqual(accounts[0]["email"], "e@example.com")
        self.assertEqual(accounts[0]["passwd"], "p")

    def test_load_accounts_from_env_single(self):
        with mock.patch.dict(os.environ, {"IKUUU_EMAIL": "e@x.com", "IKUUU_PASS": "p"}, clear=False):
            accounts = mod.load_accounts({})
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0]["email"], "e@x.com")

    def test_load_accounts_from_config(self):
        cfg = {"accounts": [{"email": "e@x.com", "password": "p"}]}
        accounts = mod.load_accounts(cfg)
        self.assertEqual(accounts[0]["passwd"], "p")

    @mock.patch("ikuuuCheckIn.send_rotation_email")
    @mock.patch("ikuuuCheckIn.notify_macos")
    def test_check_password_rotation_warns(self, mock_notify, mock_email):
        cfg = {
            "mail": {
                "enabled": True,
                "password_set_date": (datetime.date.today() - datetime.timedelta(days=89)).strftime("%Y-%m-%d"),
                "rotate_days": 90,
                "rotation_warn_before_days": 7,
                "rotation_warn_interval_days": 1,
                "last_rotation_notice": "",
                "rotation_notify_email": True,
            }
        }
        mod.check_password_rotation(cfg)
        self.assertTrue(mock_notify.called)
        self.assertTrue(mock_email.called)

    @mock.patch("ikuuuCheckIn.send_rotation_email")
    @mock.patch("ikuuuCheckIn.notify_macos")
    @mock.patch("ikuuuCheckIn.get_captcha_api_key", return_value="key")
    def test_check_captcha_key_rotation_warns(self, _key, mock_notify, mock_email):
        cfg = {
            "login": {
                "captcha_solver": {
                    "enabled": True,
                    "api_key_set_date": (datetime.date.today() - datetime.timedelta(days=89)).strftime("%Y-%m-%d"),
                    "rotate_days": 90,
                    "rotation_warn_before_days": 7,
                    "rotation_warn_interval_days": 1,
                    "last_rotation_notice": "",
                    "rotation_notify_email": True,
                    "provider": "capsolver",
                }
            },
            "mail": {
                "smtp_user": "u",
                "from_addr": "u",
                "rotation_notify_to": "u",
            },
        }
        mod.check_captcha_key_rotation(cfg)
        self.assertTrue(mock_notify.called)
        self.assertTrue(mock_email.called)


if __name__ == "__main__":
    unittest.main()
