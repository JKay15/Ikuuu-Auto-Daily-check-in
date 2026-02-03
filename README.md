# IKUUU 自动签到脚本

**简介**
该脚本会自动登录 IKUUU 并执行每日签到，同时自动发现可用域名，支持验证码解码服务、邮件获取最新地址、域名成功率排序、以及到期轮换提醒。

**功能特性**
- 自动登录与签到
- 按成功率/最近成功等策略排序域名并自动切换
- 从登录页与脚本内容自动发现新域名
- 通过邮件探测最新地址（可选）
- GeeTest 验证码解码（可选：CapSolver / AntiCaptcha）
- 密钥与邮箱 App Password 轮换提醒
- macOS 通知（可选，失败不影响主流程）

**运行环境**
- Python 3.8+
- 依赖库：`requests`

**快速开始**
1. 安装依赖

```bash
pip install requests
```

2. 准备配置
在本地准备 `config.json`，可基于 `config.example.json` 填写。  
也可以用环境变量提供账号信息（见下文）。

3. 运行脚本

```bash
python ikuuuCheckIn.py
```

**账号配置方式**
你可以二选一：
- 环境变量（推荐）
- `config.json` 中的 `accounts`

环境变量示例：

```bash
export IKUUU_EMAIL="your_email@example.com"
export IKUUU_PASS="your_ikuuu_password"
python ikuuuCheckIn.py
```

多账号 JSON 示例：

```bash
export IKUUU_ACCOUNTS='[
  {"name":"main","email":"a@example.com","passwd":"p1"},
  {"name":"backup","email":"b@example.com","passwd":"p2"}
]'
```

也支持简化字符串数组：

```bash
export IKUUU_ACCOUNTS='["a@example.com&p1","b@example.com&p2"]'
```

**环境变量清单**
| 变量 | 作用 | 备注 |
| --- | --- | --- |
| `IKUUU_ACCOUNTS` | 多账号 JSON 列表 | 最高优先级 |
| `ACCOUNTS` | `IKUUU_ACCOUNTS` 的别名 | 可选 |
| `IKUUU_EMAIL` | 单账号邮箱 | 与 `IKUUU_PASS` 搭配 |
| `IKUUU_PASS` | 单账号密码 | 与 `IKUUU_EMAIL` 搭配 |
| `IKUUU_CAPSOLVER_API_KEY` | CapSolver API Key | 验证码解码 |
| `CAPSOLVER_API_KEY` | CapSolver API Key | 备用变量名 |
| `IKUUU_ANTICAPTCHA_API_KEY` | AntiCaptcha API Key | 验证码解码 |
| `ANTICAPTCHA_API_KEY` | AntiCaptcha API Key | 备用变量名 |
| `ANTI_CAPTCHA_API_KEY` | AntiCaptcha API Key | 备用变量名 |
| `IKUUU_GMAIL_APP_PASSWORD` | Gmail App Password | 邮件探测与提醒 |
| `IKUUU_EMAIL_PASS` | Gmail App Password | 备用变量名 |
| `IKUUU_FORCE_DOMAIN` | 强制优先尝试域名 | 逗号分隔 |
| `IKUUU_FORCE_DOMAINS` | `IKUUU_FORCE_DOMAIN` 别名 | 逗号分隔 |
| `IKUUU_VERBOSE` | 额外日志输出 | `true/false` |
| `IKUUU_DUMP_HTML` | 保存登录页 HTML | `true/false` |
| `IKUUU_DUMP_HTML_DIR` | HTML 保存目录 | 默认 `debug_html/` |

说明：脚本还会尝试从 `crontab -l` 中读取纯 `KEY=VALUE` 形式的环境变量（仅在未设置系统环境变量时）。

**配置文件说明（`config.json`）**
`config.json` 同时承担“配置 + 运行状态缓存”职责，包含域名成功率与最近成功记录。为了避免泄露隐私，仓库已忽略该文件。

**顶层字段**
| 字段 | 作用 | 备注 |
| --- | --- | --- |
| `accounts` | 账号列表 | 可被环境变量覆盖 |
| `debug` | 调试选项 | 控制 HTML dump 与强制域名 |
| `domain_ordering` | 域名排序策略 | 影响优先尝试顺序 |
| `domains` | 域名统计缓存 | 自动维护，无需手改 |
| `last_success_domain` | 最近成功域名 | 自动维护 |
| `last_success_date` | 最近成功日期 | 格式 `YYYY-MM-DD` |
| `login` | 登录相关配置 | 验证码等 |
| `mail` | 邮件探测与提醒 | 可选功能 |
| `seed_domains` | 初始候选域名 | 可扩展 |
| `verbose` | 详细日志 | 布尔值 |

**accounts 字段**
| 字段 | 作用 | 备注 |
| --- | --- | --- |
| `name` | 账号名称 | 可选 |
| `email` | 登录邮箱 | 必填 |
| `passwd` | 登录密码 | 必填 |

**debug 字段**
| 字段 | 作用 | 备注 |
| --- | --- | --- |
| `dump_html` | 是否保存登录页 HTML | 与 `IKUUU_DUMP_HTML` 二选一 |
| `dump_dir` | HTML 保存目录 | 默认 `debug_html/` |
| `force_domains` | 强制优先尝试域名 | 使用后会自动清空 |

**domain_ordering 字段**
| 字段 | 作用 | 备注 |
| --- | --- | --- |
| `mode` | 排序模式 | `success_rate` / `recent_success` / `success_count` / `recent_checked` |

**domains 字段（每个域名条目）**
| 字段 | 作用 | 备注 |
| --- | --- | --- |
| `success_count` | 成功次数 | 自动维护 |
| `fail_count` | 失败次数 | 自动维护 |
| `last_success` | 最近成功日期 | `YYYY-MM-DD` |
| `last_failure` | 最近失败日期 | `YYYY-MM-DD` |
| `last_checked` | 最近尝试日期 | `YYYY-MM-DD` |

**login 字段**
| 字段 | 作用 | 备注 |
| --- | --- | --- |
| `ignore_captcha` | 遇到验证码直接失败 | 适合快速排除 |
| `two_fa_code` | 二次验证码 | 需要时填写 |
| `captcha_result` | 手工验证码结果 | JSON 对象 |
| `remember_me` | 登录保持 | 默认 `off` |
| `captcha_solver` | 自动解码服务 | 见下表 |

**login.captcha_solver 字段**
| 字段 | 作用 | 备注 |
| --- | --- | --- |
| `enabled` | 是否启用解码 | `true/false` |
| `provider` | 主服务商 | `capsolver` / `anticaptcha` |
| `fallback_provider` | 备用服务商 | `anticaptcha` |
| `timeout_seconds` | 解码超时 | 秒 |
| `poll_interval_seconds` | 轮询间隔 | 秒 |
| `api_key_set_date` | API Key 启用日期 | `YYYY-MM-DD` |
| `rotate_days` | 轮换周期 | 天 |
| `rotation_warn_before_days` | 提前提醒天数 | 天 |
| `rotation_warn_interval_days` | 提醒间隔 | 天 |
| `last_rotation_notice` | 最近提醒日期 | `YYYY-MM-DD` |
| `rotation_pending` | 是否待轮换 | 自动维护 |
| `rotation_notify_email` | 邮件提醒 | 需要 mail 配置 |

**mail 字段**
| 字段 | 作用 | 备注 |
| --- | --- | --- |
| `enabled` | 是否启用邮件探测 | `true/false` |
| `confirm_before_send` | 发送前确认 | `true` 时需 `confirmed=true` |
| `confirmed` | 已确认发送 | 未确认会阻止发送 |
| `pending_send` | 等待确认状态 | 自动维护 |
| `last_mail_attempt` | 最近尝试日期 | `YYYY-MM-DD` |
| `last_mail_sent` | 最近发送日期 | `YYYY-MM-DD` |
| `password_set_date` | App Password 启用日期 | `YYYY-MM-DD` |
| `rotate_days` | 轮换周期 | 天 |
| `rotation_pending` | 是否待轮换 | 自动维护 |
| `rotation_warn_before_days` | 提前提醒天数 | 天 |
| `rotation_warn_interval_days` | 提醒间隔 | 天 |
| `last_rotation_notice` | 最近提醒日期 | `YYYY-MM-DD` |
| `rotation_notify_email` | 邮件提醒 | `true/false` |
| `rotation_notify_to` | 提醒收件人 | 默认使用 `smtp_user` |
| `smtp_user` | SMTP 用户名 | 通常是邮箱地址 |
| `smtp_host` | SMTP 主机 | 默认 Gmail |
| `smtp_port` | SMTP 端口 | 默认 587 |
| `imap_user` | IMAP 用户名 | 通常是邮箱地址 |
| `imap_host` | IMAP 主机 | 默认 Gmail |
| `imap_folder` | IMAP 目录 | 默认 `INBOX` |
| `from_addr` | 发件人 | 空则使用 `smtp_user` |
| `to_addr` | 探测收件人 | 默认 `find@ikuuu.pro` |
| `subject` | 邮件主题 | 默认 `获取最新地址` |
| `body` | 邮件正文 | 默认 `hi` |
| `poll_seconds` | 轮询总时长 | 秒 |
| `poll_interval` | 轮询间隔 | 秒 |

**隐私与安全**
- 日志可能包含账号与密码信息，仓库已忽略所有 `.log` 文件。
- `config.json` 会持久化运行状态与账号信息，仓库已忽略该文件。
- 建议使用环境变量保存敏感信息，并定期轮换密码与 API Key。

**测试**

```bash
python -m unittest
```

**如果觉得好用**
欢迎 Star 支持一下，这能让我更有动力继续维护。
