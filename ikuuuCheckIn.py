#!/Library/Frameworks/Python.framework/Versions/3.8/bin/python3
# coding=UTF-8
import datetime
import email
import imaplib
import json
import os
import re
import smtplib
import subprocess
import time
import base64
from urllib.parse import urlparse

import requests

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
DEFAULT_SEEDS = [
    "https://ikuuu.nl",
    "https://ikuuu.fyi",
    "https://ikuuu.de",
    "https://ikuuu.one",
    "https://ikuuu.pro",
]

HEADERS = {
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
}

URL_RE = re.compile(r"https?://[^\s\'\"<>]+", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
STRING_LITERAL_RE = re.compile(r"'([^']*)'|\"([^\"]*)\"", re.S)
CONCAT_RE = re.compile(
    r"(?:'[^']*'|\"[^\"]*\")\s*(?:\+\s*(?:'[^']*'|\"[^\"]*\"))+",
    re.S,
)
ORIGIN_BODY_RE = re.compile(r'originBody\s*=\s*"([^"]+)"', re.I)
CAPTCHA_ID_RE = re.compile(r"captchaId\s*[:=]\s*['\"]([a-f0-9]{16,})['\"]", re.I)
CAPTCHA_ID_ALT_RE = re.compile(r"captcha_id\s*[:=]\s*['\"]([a-f0-9]{16,})['\"]", re.I)
GT_RE = re.compile(r"\bgt\s*[:=]\s*['\"]([a-f0-9]{16,})['\"]", re.I)
RISK_TYPE_RE = re.compile(r"riskType\s*[:=]\s*['\"]([^'\"]+)['\"]", re.I)
HIDDEN_INPUT_RE = re.compile(
    r"<input[^>]+type=[\"']hidden[\"'][^>]*>", re.I
)
NAME_RE = re.compile(r"name=[\"']([^\"']+)[\"']", re.I)
VALUE_RE = re.compile(r"value=[\"']([^\"']*)[\"']", re.I)
META_CSRF_RE = re.compile(
    r"<meta[^>]+name=[\"']csrf-token[\"'][^>]*content=[\"']([^\"']+)[\"']",
    re.I,
)
CAPTCHA_RE = re.compile(
    r"captcha|验证码|recaptcha|hcaptcha|geetest|initgeetest|captcha_result",
    re.I,
)


def now():
    return datetime.datetime.now()


def today_str():
    return now().strftime("%Y-%m-%d")


def init_stats():
    return {
        "start_ts": time.time(),
        "domain_attempts": 0,
        "login_attempts": 0,
        "login_success": 0,
        "login_page_fetches": 0,
        "login_page_fetch_failures": 0,
        "login_page_durations": [],
        "captcha_detected": False,
        "captcha_solve_attempts": 0,
        "captcha_solve_success": 0,
        "captcha_provider": "",
        "captcha_solve_duration": 0.0,
        "captcha_error": "",
        "checkin_attempts": 0,
        "checkin_success": 0,
        "html_discovered": set(),
        "email_discovered": set(),
        "email_send_attempted": False,
        "email_send_sent": False,
        "email_confirm_required": False,
        "email_poll_attempted": False,
        "email_poll_duration": 0.0,
        "rotation_pending": False,
        "rotation_notice": "",
        "selected_base_url": "",
        "result": "",
        "result_detail": "",
        "login_durations": [],
        "checkin_durations": [],
    }


def format_duration(seconds):
    if seconds is None:
        return "n/a"
    return f"{seconds:.2f}s"


def build_health_report(stats, account_index=None, total_accounts=None):
    total = time.time() - stats.get("start_ts", time.time())
    avg_login = None
    if stats.get("login_durations"):
        avg_login = sum(stats["login_durations"]) / len(stats["login_durations"])
    avg_login_page = None
    if stats.get("login_page_durations"):
        avg_login_page = sum(stats["login_page_durations"]) / len(stats["login_page_durations"])
    avg_checkin = None
    if stats.get("checkin_durations"):
        avg_checkin = sum(stats["checkin_durations"]) / len(stats["checkin_durations"])

    header = "健康检查"
    if account_index and total_accounts:
        header += f" ({account_index}/{total_accounts})"
    result = stats.get("result", "")
    detail = stats.get("result_detail", "")
    lines = [
        f"{header}: result={result} {detail}".strip(),
        "耗时: total="
        + format_duration(total)
        + " avg_login="
        + format_duration(avg_login)
        + " avg_login_page="
        + format_duration(avg_login_page)
        + " avg_checkin="
        + format_duration(avg_checkin),
        "域名尝试: "
        + str(stats.get("domain_attempts", 0))
        + " 登录成功: "
        + str(stats.get("login_success", 0))
        + " HTML发现: "
        + str(len(stats.get("html_discovered", [])))
        + " 邮件发现: "
        + str(len(stats.get("email_discovered", []))),
        "登录页: fetch="
        + str(stats.get("login_page_fetches", 0))
        + " 失败="
        + str(stats.get("login_page_fetch_failures", 0))
        + " captcha="
        + ("是" if stats.get("captcha_detected") else "否")
        + " 解码="
        + ("是" if stats.get("captcha_solve_success") else "否"),
        "邮件: 发送尝试="
        + ("是" if stats.get("email_send_attempted") else "否")
        + " 已发送="
        + ("是" if stats.get("email_send_sent") else "否")
        + " 需确认="
        + ("是" if stats.get("email_confirm_required") else "否"),
        "轮换: pending=" + ("是" if stats.get("rotation_pending") else "否"),
    ]
    if stats.get("selected_base_url"):
        lines.append("使用域名: " + stats["selected_base_url"])
    return lines


def print_health_report(stats, account_index=None, total_accounts=None):
    for line in build_health_report(stats, account_index, total_accounts):
        print(line)


def load_config():
    global _VERBOSE
    cfg = {
        "last_success_domain": "",
        "last_success_date": "",
        "domains": {},
        "seed_domains": list(DEFAULT_SEEDS),
        "accounts": [],
        "debug": {
            "dump_html": False,
            "dump_dir": "debug_html",
            "force_domains": [],
        },
        "login": {
            "ignore_captcha": False,
            "two_fa_code": "",
            "captcha_result": {},
            "remember_me": "off",
            "captcha_solver": {
                "enabled": False,
                "provider": "capsolver",
                "fallback_provider": "anticaptcha",
                "timeout_seconds": 120,
                "poll_interval_seconds": 3,
                "api_key_set_date": "",
                "rotate_days": 90,
                "rotation_warn_before_days": 7,
                "rotation_warn_interval_days": 1,
                "last_rotation_notice": "",
                "rotation_pending": False,
                "rotation_notify_email": True,
            },
        },
        "mail": {
            "enabled": True,
            "confirm_before_send": True,
            "confirmed": False,
            "pending_send": False,
            "last_mail_attempt": "",
            "last_mail_sent": "",
            "password_set_date": "",
            "rotate_days": 90,
            "rotation_pending": False,
            "rotation_warn_before_days": 7,
            "rotation_warn_interval_days": 1,
            "last_rotation_notice": "",
            "rotation_notify_email": True,
            "rotation_notify_to": "",
            "smtp_user": "",
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "imap_user": "",
            "imap_host": "imap.gmail.com",
            "imap_folder": "INBOX",
            "from_addr": "",
            "to_addr": "find@ikuuu.pro",
            "subject": "获取最新地址",
            "body": "hi",
            "poll_seconds": 30,
            "poll_interval": 5,
        },
    }
    if not os.path.exists(CONFIG_PATH):
        save_config(cfg)
        _VERBOSE = bool(cfg.get("verbose", False))
        return cfg
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            cfg.update(data)
        # ensure keys exist
        cfg.setdefault("domains", {})
        cfg.setdefault("seed_domains", list(DEFAULT_SEEDS))
        cfg.setdefault("mail", {})
        cfg.setdefault("login", {})
        cfg.setdefault("accounts", [])
        cfg.setdefault("debug", {"dump_html": False, "dump_dir": "debug_html", "force_domains": []})
        cfg.setdefault("verbose", False)
    except Exception:
        # fallback to defaults if file is broken
        _VERBOSE = bool(cfg.get("verbose", False))
        return cfg
    _VERBOSE = bool(cfg.get("verbose", False))
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2, sort_keys=True)


def load_accounts(cfg):
    accounts = []
    env_json = os.environ.get("IKUUU_ACCOUNTS") or os.environ.get("ACCOUNTS")
    if env_json:
        try:
            data = json.loads(env_json)
            if isinstance(data, list):
                accounts = data
        except Exception:
            print("账户信息环境变量格式错误，请检查 IKUUU_ACCOUNTS/ACCOUNTS")
            return []
    else:
        single_email = os.environ.get("IKUUU_EMAIL")
        single_pass = os.environ.get("IKUUU_PASS")
        if single_email and single_pass:
            accounts = [{"email": single_email, "passwd": single_pass}]
        elif isinstance(cfg, dict) and cfg.get("accounts"):
            accounts = cfg.get("accounts") or []

    normalized = []
    for item in accounts:
        if isinstance(item, str):
            if "&" not in item:
                continue
            email_addr, passwd = item.split("&", 1)
            normalized.append({"name": "", "email": email_addr, "passwd": passwd})
            continue
        if not isinstance(item, dict):
            continue
        email_addr = item.get("email") or item.get("user")
        passwd = item.get("passwd") or item.get("password")
        name = item.get("name") or ""
        if email_addr and passwd:
            normalized.append({"name": name, "email": email_addr, "passwd": passwd})
    return normalized


def normalize_domain(value):
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    try:
        parsed = urlparse(value)
    except Exception:
        return None
    if not parsed.netloc:
        return None
    scheme = parsed.scheme or "https"
    host = parsed.netloc.lower().rstrip(".")
    return f"{scheme}://{host}"


def ensure_domain_entry(cfg, domain):
    domain = normalize_domain(domain)
    if not domain:
        return None
    domains = cfg.setdefault("domains", {})
    if domain not in domains:
        domains[domain] = {
            "success_count": 0,
            "fail_count": 0,
            "last_success": "",
            "last_failure": "",
            "last_checked": "",
        }
    return domain


def record_result(cfg, domain, success):
    domain = ensure_domain_entry(cfg, domain)
    if not domain:
        return
    entry = cfg["domains"][domain]
    entry["last_checked"] = today_str()
    if success is None:
        return
    if success:
        entry["success_count"] = int(entry.get("success_count", 0)) + 1
        entry["last_success"] = today_str()
    else:
        entry["fail_count"] = int(entry.get("fail_count", 0)) + 1
        entry["last_failure"] = today_str()


def parse_date(value):
    if not value:
        return None
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


def domain_score(entry, mode="success_rate"):
    success_count = int(entry.get("success_count", 0))
    fail_count = int(entry.get("fail_count", 0))
    total = success_count + fail_count
    success_rate = (success_count / total) if total else 0
    last_success = parse_date(entry.get("last_success"))
    last_success_ts = last_success.toordinal() if last_success else 0
    last_checked = parse_date(entry.get("last_checked"))
    last_checked_ts = last_checked.toordinal() if last_checked else 0
    # Order by configured mode, then recency, then volume.
    if mode == "recent_success":
        return (last_success_ts, success_rate, success_count, last_checked_ts, -fail_count)
    if mode == "success_count":
        return (success_count, success_rate, last_success_ts, last_checked_ts, -fail_count)
    if mode == "recent_checked":
        return (last_checked_ts, success_rate, last_success_ts, success_count, -fail_count)
    # default: success_rate
    return (success_rate, last_success_ts, success_count, last_checked_ts, -fail_count)


def is_ikuuu_domain(domain):
    normalized = normalize_domain(domain)
    if not normalized:
        return False
    host = urlparse(normalized).netloc.lower()
    return "ikuuu" in host


def get_candidates(cfg):
    candidates = []
    seen = set()
    ordering = cfg.get("domain_ordering") or {}
    if isinstance(ordering, str):
        ordering = {"mode": ordering}
    mode = ordering.get("mode", "success_rate")

    def add(item):
        if not is_ikuuu_domain(item):
            return
        domain = normalize_domain(item)
        if domain and domain not in seen:
            candidates.append(domain)
            seen.add(domain)

    add(cfg.get("last_success_domain"))
    for domain, entry in sorted(
        ((d, e) for d, e in cfg.get("domains", {}).items() if is_ikuuu_domain(d)),
        key=lambda kv: domain_score(kv[1], mode=mode),
        reverse=True,
    ):
        add(domain)
    for seed in cfg.get("seed_domains", DEFAULT_SEEDS):
        add(seed)

    return candidates


def extract_domains_from_text(text):
    if not text:
        return []
    found = set()
    for url in URL_RE.findall(text):
        found.add(url)
    for dom in DOMAIN_RE.findall(text):
        found.add(dom)
    results = []
    for item in found:
        domain = normalize_domain(item)
        if not domain:
            continue
        host = urlparse(domain).netloc.lower()
        if not DOMAIN_RE.search(host):
            continue
        if "ikuuu" not in host:
            continue
        results.append(domain)
    return results


def _unescape_js_string(value):
    if value is None:
        return ""
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except Exception:
        return value


def extract_domains_from_scripts(text):
    if not text:
        return []
    found = set()
    for match in CONCAT_RE.finditer(text):
        literal_block = match.group(0)
        parts = []
        for sm in STRING_LITERAL_RE.finditer(literal_block):
            parts.append(_unescape_js_string(sm.group(1) or sm.group(2)))
        if parts:
            combined = "".join(parts)
            for dom in extract_domains_from_text(combined):
                found.add(dom)
    for sm in STRING_LITERAL_RE.finditer(text):
        literal = _unescape_js_string(sm.group(1) or sm.group(2))
        if "ikuuu" not in literal:
            continue
        for dom in extract_domains_from_text(literal):
            found.add(dom)
    return list(found)


def extract_origin_body(html):
    if not html:
        return None
    match = ORIGIN_BODY_RE.search(html)
    if not match:
        return None
    encoded = match.group(1)
    try:
        decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
        return decoded
    except Exception:
        return None


def extract_hidden_inputs(html):
    if not html:
        return {}
    tokens = {}
    for match in HIDDEN_INPUT_RE.findall(html):
        name_match = NAME_RE.search(match)
        value_match = VALUE_RE.search(match)
        if not name_match:
            continue
        name = name_match.group(1)
        value = value_match.group(1) if value_match else ""
        tokens[name] = value
    return tokens


def extract_csrf_token(html):
    if not html:
        return None
    meta = META_CSRF_RE.search(html)
    if meta:
        return meta.group(1)
    return None


def extract_geetest_params(html):
    if not html:
        return None, {}
    captcha_id = None
    for regex in (CAPTCHA_ID_RE, CAPTCHA_ID_ALT_RE, GT_RE):
        match = regex.search(html)
        if match:
            captcha_id = match.group(1)
            break
    init_params = {}
    risk = RISK_TYPE_RE.search(html)
    if risk:
        init_params["riskType"] = risk.group(1)
    return captcha_id, init_params


def get_captcha_api_key(provider):
    api_key = None
    if provider == "capsolver":
        api_key = (
            os.environ.get("IKUUU_CAPSOLVER_API_KEY")
            or os.environ.get("CAPSOLVER_API_KEY")
        )
    if provider == "anticaptcha":
        api_key = (
            os.environ.get("IKUUU_ANTICAPTCHA_API_KEY")
            or os.environ.get("ANTICAPTCHA_API_KEY")
            or os.environ.get("ANTI_CAPTCHA_API_KEY")
        )
    if api_key:
        return api_key
    # Fallback: read from user crontab env lines (for local runs).
    cron_key = None
    if provider == "capsolver":
        cron_key = get_cron_env("IKUUU_CAPSOLVER_API_KEY")
    elif provider == "anticaptcha":
        cron_key = get_cron_env("IKUUU_ANTICAPTCHA_API_KEY")
    return cron_key


def solve_captcha_capsolver(base_url, captcha_id, solver_cfg, stats=None):
    api_key = get_captcha_api_key("capsolver")
    if not api_key:
        return None, "缺少 CAPSOLVER_API_KEY"
    create_url = "https://api.capsolver.com/createTask"
    result_url = "https://api.capsolver.com/getTaskResult"
    task = {
        "type": "GeeTestTaskProxyLess",
        "websiteURL": base_url + "/auth/login",
        "captchaId": captcha_id,
    }
    payload = {"clientKey": api_key, "task": task}
    try:
        resp = requests.post(create_url, json=payload, timeout=30)
        data = resp.json()
    except Exception as e:
        return None, f"CapSolver createTask异常: {repr(e)}"
    if data.get("errorId", 0) != 0:
        return None, f"CapSolver createTask失败: {data.get('errorDescription', '')}"
    task_id = data.get("taskId")
    if not task_id:
        return None, "CapSolver 未返回 taskId"

    timeout = int(solver_cfg.get("timeout_seconds", 120))
    interval = int(solver_cfg.get("poll_interval_seconds", 3))
    start = time.time()
    while time.time() - start < timeout:
        time.sleep(max(interval, 1))
        try:
            resp = requests.post(
                result_url, json={"clientKey": api_key, "taskId": task_id}, timeout=30
            )
            data = resp.json()
        except Exception as e:
            return None, f"CapSolver getTaskResult异常: {repr(e)}"
        if data.get("errorId", 0) != 0:
            return None, f"CapSolver getTaskResult失败: {data.get('errorDescription', '')}"
        if data.get("status") == "ready":
            return data.get("solution"), None
    return None, "CapSolver 解码超时"


def solve_captcha_anticaptcha(base_url, captcha_id, init_params, solver_cfg):
    api_key = get_captcha_api_key("anticaptcha")
    if not api_key:
        return None, "缺少 ANTICAPTCHA_API_KEY"
    create_url = "https://api.anti-captcha.com/createTask"
    result_url = "https://api.anti-captcha.com/getTaskResult"
    task = {
        "type": "GeeTestTaskProxyless",
        "websiteURL": base_url + "/auth/login",
        "gt": captcha_id,
        "version": 4,
    }
    if init_params:
        task["initParameters"] = init_params
    payload = {"clientKey": api_key, "task": task}
    try:
        resp = requests.post(create_url, json=payload, timeout=30)
        data = resp.json()
    except Exception as e:
        return None, f"Anti-Captcha createTask异常: {repr(e)}"
    if data.get("errorId", 0) != 0:
        return None, f"Anti-Captcha createTask失败: {data.get('errorDescription', '')}"
    task_id = data.get("taskId")
    if not task_id:
        return None, "Anti-Captcha 未返回 taskId"

    timeout = int(solver_cfg.get("timeout_seconds", 120))
    interval = int(solver_cfg.get("poll_interval_seconds", 3))
    start = time.time()
    while time.time() - start < timeout:
        time.sleep(max(interval, 1))
        try:
            resp = requests.post(
                result_url, json={"clientKey": api_key, "taskId": task_id}, timeout=30
            )
            data = resp.json()
        except Exception as e:
            return None, f"Anti-Captcha getTaskResult异常: {repr(e)}"
        if data.get("errorId", 0) != 0:
            return None, f"Anti-Captcha getTaskResult失败: {data.get('errorDescription', '')}"
        if data.get("status") == "ready":
            return data.get("solution"), None
    return None, "Anti-Captcha 解码超时"


def solve_geetest_v4(base_url, captcha_id, init_params, solver_cfg, stats=None):
    providers = []
    primary = solver_cfg.get("provider", "capsolver")
    fallback = solver_cfg.get("fallback_provider")
    if primary:
        providers.append(primary)
    if fallback and fallback not in providers:
        providers.append(fallback)

    attempted = 0
    last_err = None
    for provider in providers:
        if provider in ("capsolver", "anticaptcha") and not get_captcha_api_key(provider):
            continue
        if stats is not None:
            stats["captcha_solve_attempts"] += 1
            stats["captcha_provider"] = provider
        start = time.time()
        attempted += 1
        if provider == "capsolver":
            solution, err = solve_captcha_capsolver(base_url, captcha_id, solver_cfg, stats=stats)
        elif provider == "anticaptcha":
            solution, err = solve_captcha_anticaptcha(base_url, captcha_id, init_params, solver_cfg)
        else:
            solution, err = None, f"未知captcha provider: {provider}"

        if stats is not None:
            stats["captcha_solve_duration"] += time.time() - start

        if solution:
            if stats is not None:
                stats["captcha_solve_success"] += 1
            return solution, None

        last_err = err or ""
        if stats is not None:
            stats["captcha_error"] = last_err

    if attempted == 0:
        return None, "未配置验证码服务API Key"
    return None, last_err or "captcha solve failed"


def detect_captcha(html):
    if not html:
        return False
    return bool(CAPTCHA_RE.search(html))


def is_already_checked_in(msg):
    if not msg:
        return False
    low = str(msg).lower()
    patterns = ["已签到", "已经签到", "已簽到", "已签", "已簽", "已打卡", "already"]
    return any(p in msg for p in patterns) or "already" in low


def get_forced_domains(cfg=None):
    env = os.environ.get("IKUUU_FORCE_DOMAIN") or os.environ.get("IKUUU_FORCE_DOMAINS")
    forced = []
    from_config = False
    if env:
        forced = [item.strip() for item in env.split(",") if item.strip()]
    elif cfg and isinstance(cfg, dict):
        debug_cfg = cfg.get("debug") or {}
        forced = debug_cfg.get("force_domains") or []
        if forced:
            from_config = True
    normalized = []
    for item in forced:
        domain = normalize_domain(item)
        if domain:
            normalized.append(domain)
    return list(dict.fromkeys(normalized)), from_config


def discover_from_html(base_url, stats=None, cfg=None):
    discovered = []
    for path in ("/", "/auth/login"):
        try:
            resp = requests.get(
                base_url + path,
                headers=HEADERS,
                timeout=12,
                allow_redirects=True,
            )
        except Exception:
            continue
        if is_html_dump_enabled(cfg):
            label = "root" if path == "/" else path.strip("/").replace("/", "_")
            dump_html(label, base_url, resp.text, cfg=cfg)
        # include final redirected domain
        discovered.extend(extract_domains_from_text(resp.url))
        text_domains = extract_domains_from_text(resp.text)
        if text_domains:
            discovered.extend(text_domains)
        else:
            discovered.extend(extract_domains_from_scripts(resp.text))
        decoded_html = extract_origin_body(resp.text)
        if decoded_html:
            decoded_text = extract_domains_from_text(decoded_html)
            if decoded_text:
                discovered.extend(decoded_text)
            else:
                discovered.extend(extract_domains_from_scripts(decoded_html))
            if is_html_dump_enabled(cfg):
                label = "root" if path == "/" else path.strip("/").replace("/", "_")
                dump_html(label, base_url, decoded_html, cfg=cfg, suffix="_decoded")
    discovered = list(dict.fromkeys(discovered))
    # Remove the current base_url and de-dup for new discovery.
    base_norm = normalize_domain(base_url)
    if base_norm:
        discovered = [d for d in discovered if d != base_norm]
    # Persist discovered domains for future attempts.
    if cfg is not None:
        for domain in discovered:
            ensure_domain_entry(cfg, domain)
            seeds = cfg.setdefault("seed_domains", list(DEFAULT_SEEDS))
            if domain not in seeds:
                seeds.append(domain)
    if stats is not None:
        stats["html_discovered"].update(discovered)
    return discovered


def get_mail_password():
    return (
        os.environ.get("IKUUU_GMAIL_APP_PASSWORD")
        or os.environ.get("IKUUU_EMAIL_PASS")
        or get_cron_env("IKUUU_GMAIL_APP_PASSWORD")
        or get_cron_env("IKUUU_EMAIL_PASS")
    )


_CRON_ENV_CACHE = None
_CRON_ENV_NOTIFIED = set()
_VERBOSE = None


def is_verbose():
    env = (os.environ.get("IKUUU_VERBOSE") or "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    if env in ("0", "false", "no", "off"):
        return False
    return bool(_VERBOSE)


def is_html_dump_enabled(cfg=None):
    env = (os.environ.get("IKUUU_DUMP_HTML") or "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    if env in ("0", "false", "no", "off"):
        return False
    if cfg and isinstance(cfg, dict):
        debug_cfg = cfg.get("debug") or {}
        return bool(debug_cfg.get("dump_html", False))
    return False


def get_dump_dir(cfg=None):
    env_dir = os.environ.get("IKUUU_DUMP_HTML_DIR")
    if env_dir:
        dump_dir = env_dir
    elif cfg and isinstance(cfg, dict):
        debug_cfg = cfg.get("debug") or {}
        dump_dir = debug_cfg.get("dump_dir") or "debug_html"
    else:
        dump_dir = "debug_html"
    if not os.path.isabs(dump_dir):
        dump_dir = os.path.join(os.path.dirname(__file__), dump_dir)
    os.makedirs(dump_dir, exist_ok=True)
    return dump_dir


def dump_html(label, base_url, content, cfg=None, suffix=""):
    if not content:
        return None
    dump_dir = get_dump_dir(cfg)
    host = urlparse(base_url).netloc or "unknown"
    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label or "page")
    safe_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", host)
    ts = time.strftime("%Y%m%d_%H%M%S")
    name = f"{ts}_{safe_label}_{safe_host}{suffix}.html"
    path = os.path.join(dump_dir, name)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print("HTML已保存:", path)
        return path
    except Exception:
        return None


def get_cron_env(key):
    global _CRON_ENV_CACHE
    if _CRON_ENV_CACHE is None:
        _CRON_ENV_CACHE = {}
        try:
            output = subprocess.check_output(["crontab", "-l"], stderr=subprocess.STDOUT)
            for line in output.decode("utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if " " in line:
                    # Only parse pure KEY=VALUE lines (no schedule).
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if not k:
                    continue
                _CRON_ENV_CACHE[k] = v.strip()
        except Exception:
            pass
    value = _CRON_ENV_CACHE.get(key)
    if value and key not in _CRON_ENV_NOTIFIED and is_verbose():
        print("已从crontab读取环境变量:", key)
        _CRON_ENV_NOTIFIED.add(key)
    return value


def check_password_rotation(cfg, stats=None):
    mail_cfg = cfg.get("mail", {})
    if not mail_cfg.get("enabled"):
        return

    rotate_days = int(mail_cfg.get("rotate_days", 90))
    warn_before = int(mail_cfg.get("rotation_warn_before_days", 7))
    warn_interval = int(mail_cfg.get("rotation_warn_interval_days", 1))
    password_set_date = parse_date(mail_cfg.get("password_set_date"))
    today = now().date()
    last_notice = parse_date(mail_cfg.get("last_rotation_notice"))

    def should_notify():
        if last_notice is None:
            return True
        return (today - last_notice).days >= max(warn_interval, 1)

    def notify(title, msg):
        print(msg)
        notify_macos(title, msg)
        if mail_cfg.get("rotation_notify_email"):
            send_rotation_email(cfg, title, msg)
        mail_cfg["last_rotation_notice"] = today_str()
        if stats is not None:
            stats["rotation_notice"] = msg

    if not password_set_date:
        mail_cfg["rotation_pending"] = True
        if stats is not None:
            stats["rotation_pending"] = True
        if should_notify():
            notify(
                "IKUUU 邮箱密码提醒",
                "未设置邮件App Password启用日期。请在config.json中填写 mail.password_set_date=YYYY-MM-DD。",
            )
        return

    age_days = (today - password_set_date).days
    due_date = password_set_date + datetime.timedelta(days=rotate_days)
    if age_days >= rotate_days:
        mail_cfg["rotation_pending"] = True
        if stats is not None:
            stats["rotation_pending"] = True
        if should_notify():
            notify(
                "IKUUU 邮箱密码需轮换",
                "邮件App Password已超过轮换周期，请尽快撤销并重建，然后更新 mail.password_set_date。到期日: "
                + due_date.strftime("%Y-%m-%d"),
            )
    else:
        mail_cfg["rotation_pending"] = False
        if stats is not None:
            stats["rotation_pending"] = False
        days_left = rotate_days - age_days
        if days_left <= warn_before and should_notify():
            notify(
                "IKUUU 邮箱密码即将到期",
                "邮件App Password将在 "
                + due_date.strftime("%Y-%m-%d")
                + " 到期，请提前准备轮换。",
            )


def check_captcha_key_rotation(cfg):
    login_cfg = cfg.get("login", {})
    solver_cfg = login_cfg.get("captcha_solver", {}) if isinstance(login_cfg, dict) else {}
    if not solver_cfg.get("enabled"):
        return

    provider = solver_cfg.get("provider", "capsolver")
    api_key = get_captcha_api_key(provider)
    if not api_key:
        return

    rotate_days = int(solver_cfg.get("rotate_days", 90))
    warn_before = int(solver_cfg.get("rotation_warn_before_days", 7))
    warn_interval = int(solver_cfg.get("rotation_warn_interval_days", 1))
    key_set_date = parse_date(solver_cfg.get("api_key_set_date"))
    today = now().date()
    last_notice = parse_date(solver_cfg.get("last_rotation_notice"))

    def should_notify():
        if last_notice is None:
            return True
        return (today - last_notice).days >= max(warn_interval, 1)

    def notify(title, msg):
        print(msg)
        notify_macos(title, msg)
        if solver_cfg.get("rotation_notify_email"):
            send_rotation_email(cfg, title, msg)
        solver_cfg["last_rotation_notice"] = today_str()

    if not key_set_date:
        solver_cfg["rotation_pending"] = True
        if should_notify():
            notify(
                "IKUUU 验证码Key提醒",
                "未设置验证码服务API Key启用日期。请在config.json中填写 login.captcha_solver.api_key_set_date=YYYY-MM-DD。",
            )
        return

    age_days = (today - key_set_date).days
    due_date = key_set_date + datetime.timedelta(days=rotate_days)
    if age_days >= rotate_days:
        solver_cfg["rotation_pending"] = True
        if should_notify():
            notify(
                "IKUUU 验证码Key需轮换",
                "验证码服务API Key已超过轮换周期，请尽快撤销并重建，然后更新 login.captcha_solver.api_key_set_date。到期日: "
                + due_date.strftime("%Y-%m-%d"),
            )
    else:
        solver_cfg["rotation_pending"] = False
        days_left = rotate_days - age_days
        if days_left <= warn_before and should_notify():
            notify(
                "IKUUU 验证码Key即将到期",
                "验证码服务API Key将在 "
                + due_date.strftime("%Y-%m-%d")
                + " 到期，请提前准备轮换。",
            )


def notify_macos(title, message):
    safe_title = str(title).replace('"', '\\"')
    safe_message = str(message).replace('"', '\\"').replace("\n", " ")
    try:
        subprocess.run(
            [
                "osascript",
                "-e",
                f'display notification "{safe_message}" with title "{safe_title}"',
            ],
            check=False,
        )
    except Exception as e:
        print("发送macOS通知失败:", repr(e))


def send_rotation_email(cfg, subject, body):
    mail_cfg = cfg.get("mail", {})
    password = get_mail_password()
    if not password:
        print("未设置邮箱密码环境变量，无法发送轮换提醒邮件")
        return False
    smtp_user = mail_cfg.get("smtp_user")
    from_addr = mail_cfg.get("from_addr") or smtp_user
    to_addr = mail_cfg.get("rotation_notify_to") or mail_cfg.get("smtp_user")
    if not smtp_user or not from_addr or not to_addr:
        return False
    msg = f"From: {from_addr}\nTo: {to_addr}\nSubject: {subject}\n\n{body}"
    try:
        server = smtplib.SMTP(mail_cfg.get("smtp_host", "smtp.gmail.com"), int(mail_cfg.get("smtp_port", 587)))
        server.starttls()
        server.login(smtp_user, password)
        server.sendmail(from_addr, [to_addr], msg.encode("utf-8"))
        server.quit()
        return True
    except Exception as e:
        print("发送轮换提醒邮件失败:", repr(e))
        return False


def send_probe_email(cfg, stats=None):
    mail_cfg = cfg.get("mail", {})
    if not mail_cfg.get("enabled"):
        return False
    if stats is not None:
        stats["email_send_attempted"] = True
    if mail_cfg.get("confirm_before_send") and not mail_cfg.get("confirmed"):
        mail_cfg["pending_send"] = True
        mail_cfg["last_mail_attempt"] = today_str()
        print("需要手动确认才能发送邮件。请在config.json中设置 mail.confirmed=true 后再运行。")
        notify_macos(
            "IKUUU 需确认发送",
            "需要手动确认才能发送邮件。请在config.json中设置 mail.confirmed=true 后再运行。",
        )
        if stats is not None:
            stats["email_confirm_required"] = True
        return False
    password = get_mail_password()
    if not password:
        print("未设置邮箱密码环境变量，跳过邮件获取最新地址")
        return False
    smtp_user = mail_cfg.get("smtp_user")
    from_addr = mail_cfg.get("from_addr") or smtp_user
    to_addr = mail_cfg.get("to_addr")
    if not smtp_user or not from_addr or not to_addr:
        print("邮件配置不完整，跳过邮件获取最新地址")
        return False

    subject = mail_cfg.get("subject", "获取最新地址")
    body = mail_cfg.get("body", "hi")
    msg = f"From: {from_addr}\nTo: {to_addr}\nSubject: {subject}\n\n{body}"

    try:
        server = smtplib.SMTP(mail_cfg.get("smtp_host", "smtp.gmail.com"), int(mail_cfg.get("smtp_port", 587)))
        server.starttls()
        server.login(smtp_user, password)
        server.sendmail(from_addr, [to_addr], msg.encode("utf-8"))
        server.quit()
        print("已发送获取最新地址的邮件")
        mail_cfg["last_mail_sent"] = today_str()
        mail_cfg["last_mail_attempt"] = today_str()
        mail_cfg["pending_send"] = False
        if mail_cfg.get("confirm_before_send"):
            mail_cfg["confirmed"] = False
        if stats is not None:
            stats["email_send_sent"] = True
        return True
    except Exception as e:
        print("发送邮件失败:", repr(e))
        mail_cfg["last_mail_attempt"] = today_str()
        return False


def fetch_domains_from_email(cfg, since_dt, stats=None):
    mail_cfg = cfg.get("mail", {})
    if not mail_cfg.get("enabled"):
        return []
    password = get_mail_password()
    if not password:
        return []
    imap_user = mail_cfg.get("imap_user") or mail_cfg.get("smtp_user")
    imap_host = mail_cfg.get("imap_host", "imap.gmail.com")
    folder = mail_cfg.get("imap_folder", "INBOX")
    from_addr = mail_cfg.get("to_addr", "find@ikuuu.pro")

    if not imap_user:
        return []

    since_str = since_dt.strftime("%d-%b-%Y")
    query = f'(FROM "{from_addr}" SINCE "{since_str}")'

    try:
        imap = imaplib.IMAP4_SSL(imap_host)
        imap.login(imap_user, password)
        imap.select(folder)
        typ, data = imap.search(None, query)
        if typ != "OK":
            imap.logout()
            return []
        ids = data[0].split()
        if not ids:
            imap.logout()
            return []
        # fetch last few emails
        ids = ids[-5:]
        texts = []
        for msg_id in ids:
            typ, msg_data = imap.fetch(msg_id, "(RFC822)")
            if typ != "OK":
                continue
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)
            texts.append(extract_message_text(msg))
        imap.logout()
    except Exception as e:
        print("读取邮箱失败:", repr(e))
        return []

    found = []
    for text in texts:
        found.extend(extract_domains_from_text(text))
    # de-dup
    found = list(dict.fromkeys(found))
    if stats is not None:
        stats["email_discovered"].update(found)
    return found


def extract_message_text(msg):
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype not in ("text/plain", "text/html"):
                continue
            if part.get_filename():
                continue
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            parts.append(payload.decode(charset, errors="ignore"))
        return "\n".join(parts)
    payload = msg.get_payload(decode=True) or b""
    charset = msg.get_content_charset() or "utf-8"
    return payload.decode(charset, errors="ignore")


def log_response(prefix, resp):
    text = resp.text or ""
    if len(text) > 500:
        text = text[:500] + "..."
    print(f"{prefix}={text}")


def try_login(base_url, email_addr, passwd, stats=None, login_opts=None):
    login_opts = login_opts or {}
    body = {"email": email_addr, "password": passwd, "passwd": passwd}
    try:
        host = urlparse(base_url).netloc
        if host:
            body["host"] = host
    except Exception:
        pass
    body["pageLoadedAt"] = int(time.time() * 1000)
    two_fa_code = login_opts.get("two_fa_code")
    if two_fa_code:
        body["code"] = two_fa_code
    captcha_result = login_opts.get("captcha_result")
    if isinstance(captcha_result, dict) and captcha_result:
        body["captcha_result"] = json.dumps(captcha_result, separators=(",", ":"))
        for key, value in captcha_result.items():
            body[f"captcha_result[{key}]"] = value
    remember_me = login_opts.get("remember_me")
    if remember_me is not None:
        body["remember_me"] = remember_me
    session = requests.session()
    login_page_html = ""
    login_page_url = None
    start_page = time.time()
    try:
        page_resp = session.get(
            base_url + "/auth/login",
            headers=HEADERS,
            timeout=12,
            allow_redirects=True,
        )
        login_page_html = page_resp.text or ""
        login_page_url = page_resp.url
        if stats is not None:
            stats["login_page_fetches"] += 1
            stats["login_page_durations"].append(time.time() - start_page)
    except Exception:
        if stats is not None:
            stats["login_page_fetches"] += 1
            stats["login_page_fetch_failures"] += 1
            stats["login_page_durations"].append(time.time() - start_page)

    # augment login body with hidden inputs / csrf token if present
    analysis_html = login_page_html
    decoded_html = extract_origin_body(login_page_html)
    if decoded_html:
        analysis_html = decoded_html

    post_base_url = base_url
    login_page_domain = None
    if login_page_url:
        login_page_domain = normalize_domain(login_page_url)
        if login_page_domain and login_page_domain != base_url:
            post_base_url = login_page_domain

    if analysis_html:
        hidden = extract_hidden_inputs(analysis_html)
        if hidden:
            body.update(hidden)
        csrf = extract_csrf_token(analysis_html)
        if csrf and "_token" not in body:
            body["_token"] = csrf
        if detect_captcha(analysis_html):
            if stats is not None:
                stats["captcha_detected"] = True
            # If captcha already supplied, proceed. Otherwise try solver or fail.
            if not (isinstance(captcha_result, dict) and captcha_result):
                if login_opts.get("ignore_captcha"):
                    return (
                        False,
                        None,
                        "登录页面包含验证码(GeeTest)，已配置忽略但服务端通常会拒绝",
                        None,
                        False,
                    )
                solver_cfg = login_opts.get("captcha_solver", {}) or {}
                if not solver_cfg.get("enabled"):
                    return (
                        False,
                        None,
                        "登录页面包含验证码(GeeTest)，未启用解码服务",
                        None,
                        False,
                    )
                captcha_id, init_params = extract_geetest_params(analysis_html)
                if not captcha_id:
                    return (
                        False,
                        None,
                        "检测到验证码，但未能解析 captchaId",
                        None,
                        False,
                    )
                solution, err = solve_geetest_v4(
                    post_base_url, captcha_id, init_params, solver_cfg, stats=stats
                )
                if not solution:
                    return (
                        False,
                        None,
                        "验证码解码失败: " + (err or ""),
                        None,
                        False,
                    )
                body["captcha_result"] = json.dumps(solution, separators=(",", ":"))
                for key, value in solution.items():
                    body[f"captcha_result[{key}]"] = value
    start = time.time()
    try:
        resp = session.post(
            post_base_url + "/auth/login",
            headers=HEADERS,
            data=body,
            timeout=15,
            allow_redirects=True,
        )
    except Exception as e:
        if stats is not None:
            stats["login_attempts"] += 1
            stats["login_durations"].append(time.time() - start)
        return False, None, f"网络异常: {repr(e)}", None, False

    if getattr(resp, "status_code", None) == 405 or "405 Not Allowed" in (resp.text or ""):
        if stats is not None:
            stats["login_attempts"] += 1
            stats["login_durations"].append(time.time() - start)
        return False, None, "登录被拒绝(405)", redirect_domain, False

    redirect_domain = None
    if resp.url and resp.url != post_base_url + "/auth/login":
        redirect_domain = normalize_domain(resp.url)
    if not redirect_domain and login_page_domain and login_page_domain != base_url:
        redirect_domain = login_page_domain

    try:
        data = resp.json()
    except Exception:
        log_response("loginResp", resp)
        if stats is not None:
            stats["login_attempts"] += 1
            stats["login_durations"].append(time.time() - start)
        return False, None, "登录响应非JSON", redirect_domain, False

    log_response("loginResp", resp)
    if stats is not None:
        stats["login_attempts"] += 1
        stats["login_durations"].append(time.time() - start)
    if data.get("ret") == 1:
        if stats is not None:
            stats["login_success"] += 1
        return True, session, "登录成功", redirect_domain, False

    msg = str(data.get("msg", ""))
    low = msg.lower()
    cred_error = any(k in low for k in ["email", "password", "邮箱", "密码", "账号"]) or "密码" in msg
    return False, None, msg or "登录失败", redirect_domain, cred_error


def checkin(session, base_url, stats=None):
    start = time.time()
    try:
        resp = session.post(
            base_url + "/user/checkin",
            headers=HEADERS,
            timeout=15,
            allow_redirects=True,
        )
    except Exception as e:
        print("签到异常:", repr(e))
        if stats is not None:
            stats["checkin_attempts"] += 1
            stats["checkin_durations"].append(time.time() - start)
        return False

    try:
        data = resp.json()
    except Exception:
        log_response("checkinResp", resp)
        print("签到响应非JSON")
        if stats is not None:
            stats["checkin_attempts"] += 1
            stats["checkin_durations"].append(time.time() - start)
        return False

    log_response("checkinResp", resp)
    if stats is not None:
        stats["checkin_attempts"] += 1
        stats["checkin_durations"].append(time.time() - start)
    if data.get("ret") == 1:
        if stats is not None:
            stats["checkin_success"] += 1
        return True

    msg = str(data.get("msg", ""))
    if is_already_checked_in(msg):
        print("已签到:", msg)
        if stats is not None:
            stats["checkin_success"] += 1
        return True

    print("签到失败:", msg)
    return False


def resolve_and_login(email_addr, passwd, cfg, stats=None):
    candidates = get_candidates(cfg)
    forced, forced_from_config = get_forced_domains(cfg)
    if forced:
        # Ensure forced domains are tried first.
        for domain in reversed(forced):
            if domain in candidates:
                candidates.remove(domain)
            candidates.insert(0, domain)
        if forced_from_config:
            debug_cfg = cfg.setdefault("debug", {})
            debug_cfg["force_domains"] = []
    seen = set(candidates)

    def add_candidates(items):
        for item in items:
            if not is_ikuuu_domain(item):
                continue
            domain = normalize_domain(item)
            if domain and domain not in seen:
                ensure_domain_entry(cfg, domain)
                candidates.append(domain)
                seen.add(domain)

    # first pass: try candidates, discover from html
    while candidates:
        base_url = candidates.pop(0)
        print("尝试域名:", base_url)
        if stats is not None:
            stats["domain_attempts"] += 1
        ok, session, msg, redirect_domain, cred_error = try_login(
            base_url, email_addr, passwd, stats=stats, login_opts=cfg.get("login", {})
        )
        if redirect_domain:
            add_candidates([redirect_domain])
        if cred_error:
            print("登录失败（疑似账号密码错误），停止尝试其他域名:", msg)
            if stats is not None:
                stats["result"] = "cred_error"
                stats["result_detail"] = msg
            return None, None
        if ok:
            success_domain = redirect_domain or base_url
            if redirect_domain and redirect_domain != base_url:
                # Redirected to a different domain; credit the real domain.
                record_result(cfg, base_url, False)
                record_result(cfg, redirect_domain, True)
            else:
                record_result(cfg, base_url, True)
            cfg["last_success_domain"] = success_domain
            cfg["last_success_date"] = today_str()
            if stats is not None:
                stats["selected_base_url"] = success_domain
                stats["result"] = "login_ok"
            return success_domain, session
        record_result(cfg, base_url, False)
        print("登录失败:", msg)
        add_candidates(discover_from_html(base_url, stats=stats, cfg=cfg))

    # fallback: try email auto-discovery
    mail_cfg = cfg.get("mail", {})
    if mail_cfg.get("enabled"):
        sent = send_probe_email(cfg, stats=stats)
        if sent:
            poll_seconds = int(mail_cfg.get("poll_seconds", 30))
            poll_interval = int(mail_cfg.get("poll_interval", 5))
            deadline = time.time() + max(poll_seconds, 5)
            found_domains = []
            if stats is not None:
                stats["email_poll_attempted"] = True
                poll_start = time.time()
            while time.time() < deadline:
                found_domains = fetch_domains_from_email(
                    cfg, now() - datetime.timedelta(days=2), stats=stats
                )
                if found_domains:
                    break
                time.sleep(max(poll_interval, 1))
            if stats is not None:
                stats["email_poll_duration"] += time.time() - poll_start
            if found_domains:
                add_candidates(found_domains)

    # try any new candidates from email
    while candidates:
        base_url = candidates.pop(0)
        print("尝试域名:", base_url)
        if stats is not None:
            stats["domain_attempts"] += 1
        ok, session, msg, redirect_domain, cred_error = try_login(
            base_url, email_addr, passwd, stats=stats, login_opts=cfg.get("login", {})
        )
        if redirect_domain:
            add_candidates([redirect_domain])
        if cred_error:
            print("登录失败（疑似账号密码错误），停止尝试其他域名:", msg)
            if stats is not None:
                stats["result"] = "cred_error"
                stats["result_detail"] = msg
            return None, None
        if ok:
            success_domain = redirect_domain or base_url
            if redirect_domain and redirect_domain != base_url:
                record_result(cfg, base_url, False)
                record_result(cfg, redirect_domain, True)
            else:
                record_result(cfg, base_url, True)
            cfg["last_success_domain"] = success_domain
            cfg["last_success_date"] = today_str()
            if stats is not None:
                stats["selected_base_url"] = success_domain
                stats["result"] = "login_ok"
            return success_domain, session
        record_result(cfg, base_url, False)
        print("登录失败:", msg)

    if stats is not None and not stats.get("result"):
        stats["result"] = "no_domain"
        stats["result_detail"] = "all domains failed"

    return None, None


def main():
    print(now().strftime("%Y-%m-%d %H:%M:%S"))

    cfg = load_config()
    accounts = load_accounts(cfg)
    if not accounts:
        print("未配置账户信息，请设置 IKUUU_ACCOUNTS/IKUUU_EMAIL+IKUUU_PASS 或 config.json 的 accounts")
        return
    print("共需要签到" + str(len(accounts)) + "个账号")
    check_password_rotation(cfg)
    check_captcha_key_rotation(cfg)

    for idx, account in enumerate(accounts, start=1):
        stats = init_stats()
        stats["rotation_pending"] = cfg.get("mail", {}).get("rotation_pending", False)
        display_name = account.get("name") or f"账号{idx}"
        print("=====正在执行第" + str(idx) + "个账号(" + display_name + ")=====")
        email_addr = account.get("email")
        passwd = account.get("passwd")
        if not email_addr or not passwd:
            print("账号格式错误，跳过")
            stats["result"] = "bad_account_format"
            print_health_report(stats, idx, len(accounts))
            continue
        base_url, session = resolve_and_login(email_addr, passwd, cfg, stats=stats)
        if not base_url or not session:
            print("未找到可用域名，跳过签到")
            if not stats.get("result"):
                stats["result"] = "no_domain"
            save_config(cfg)
            print_health_report(stats, idx, len(accounts))
            continue
        print("登录成功，开始签到:", base_url)
        ok = checkin(session, base_url, stats=stats)
        if ok:
            stats["result"] = "success"
        else:
            stats["result"] = "checkin_failed"
        print("=====第" + str(idx) + "个账号，执行完毕=====")
        print_health_report(stats, idx, len(accounts))
        save_config(cfg)


if __name__ == "__main__":
    main()
