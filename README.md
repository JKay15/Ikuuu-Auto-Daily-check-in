# IKUUU 自动签到脚本

**一句话说明**
自动登录 IKUUU 并签到，自动发现新域名、根据历史成功率智能排序，支持邮件探测与提醒，支持 CapSolver 解码 GeeTest 验证码，适合配合 crontab 定时运行。

**项目亮点**
- 自动发现新域名：从登录页、脚本内容与邮件内容提取可用域名
- 智能排序域名：按成功率/最近成功/成功次数/最近检查等策略自动调整尝试顺序
- 自动化邮件：可发送探测邮件获取最新地址，支持提醒与轮换提示
- 验证码解码：内置 GeeTest v4 解析逻辑，支持 CapSolver 与 AntiCaptcha
- 低维护运行：输出健康检查摘要，适合 cron 定时

**运行环境**
- Python 3.8+
- 依赖库：`requests`

**快速开始**
1. 安装依赖

```bash
pip install requests
```

2. 准备配置
在本地准备 `config.json`，可基于 `config.example.json` 填写。也可以使用环境变量提供账号信息。

3. 运行脚本

```bash
python ikuuuCheckIn.py
```

**账号配置方式**
二选一即可：
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

简化字符串数组示例：

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
| `IKUUU_CAPSOLVER_API_KEY` | CapSolver API Key | GeeTest 解码 |
| `CAPSOLVER_API_KEY` | CapSolver API Key | 备用变量名 |
| `IKUUU_ANTICAPTCHA_API_KEY` | AntiCaptcha API Key | GeeTest 解码 |
| `ANTICAPTCHA_API_KEY` | AntiCaptcha API Key | 备用变量名 |
| `ANTI_CAPTCHA_API_KEY` | AntiCaptcha API Key | 备用变量名 |
| `IKUUU_GMAIL_APP_PASSWORD` | Gmail App Password | 邮件探测与提醒 |
| `IKUUU_EMAIL_PASS` | Gmail App Password | 备用变量名 |
| `IKUUU_FORCE_DOMAIN` | 强制优先尝试域名 | 逗号分隔 |
| `IKUUU_FORCE_DOMAINS` | `IKUUU_FORCE_DOMAIN` 别名 | 逗号分隔 |
| `IKUUU_VERBOSE` | 额外日志输出 | `true/false` |
| `IKUUU_DUMP_HTML` | 保存登录页 HTML | `true/false` |
| `IKUUU_DUMP_HTML_DIR` | HTML 保存目录 | 默认 `debug_html/` |

说明：脚本会尝试从 `crontab -l` 中读取纯 `KEY=VALUE` 的环境变量（仅在进程环境变量未提供时）。

**crontab 定时运行（推荐）**
1. 编辑定时任务

```bash
crontab -e
```

2. 参考配置（请按实际路径修改）

```bash
MAILTO=""
IKUUU_EMAIL=your_email@example.com
IKUUU_PASS=your_ikuuu_password
IKUUU_CAPSOLVER_API_KEY=your_capsolver_key
IKUUU_GMAIL_APP_PASSWORD=your_gmail_app_password
PATH=/usr/local/bin:/usr/bin:/bin

0 9 * * * /Library/Frameworks/Python.framework/Versions/3.8/bin/python3 /Users/xiongjiangkai/Desktop/精选/ikuuu/ikuuuCheckIn.py >> /Users/xiongjiangkai/Desktop/精选/ikuuu/ikuuuCheckIn.log 2>&1
```

3. 保存并退出即可生效

**Cron 说明**  
Cron 默认不会加载你的终端环境变量，所以建议在 crontab 里显式配置。  
日志可能包含敏感信息，建议把日志放在本地安全目录，且不要上传到仓库。

**验证码解码（CapSolver / AntiCaptcha）**
- 在 `config.json` 中开启 `login.captcha_solver.enabled=true`
- 设置 `login.captcha_solver.provider` 为 `capsolver` 或 `anticaptcha`
- 通过环境变量注入 API Key（上表中的 `IKUUU_CAPSOLVER_API_KEY` 或 `IKUUU_ANTICAPTCHA_API_KEY`）

**邮件探测与提醒**
- `mail.enabled=true` 开启邮件探测
- `mail.confirm_before_send=true` 时需要设置 `mail.confirmed=true` 才会真正发送
- Gmail 推荐使用 App Password，并在环境变量中设置 `IKUUU_GMAIL_APP_PASSWORD`
- 提醒与轮换逻辑会根据 `password_set_date`、`api_key_set_date` 自动判定

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

**domain_ordering.mode 支持值**
- `success_rate`
- `recent_success`
- `success_count`
- `recent_checked`

**隐私与安全**
- 日志可能包含账号与密码信息，仓库已忽略所有 `.log` 文件。
- `config.json` 会持久化运行状态与账号信息，仓库已忽略该文件。
- 建议使用环境变量保存敏感信息，并定期轮换密码与 API Key。

**测试**

```bash
/Library/Frameworks/Python.framework/Versions/3.8/bin/python3 -m unittest discover -s tests
```

**如果觉得好用**
欢迎 Star 支持一下，这能让我更有动力继续维护。
