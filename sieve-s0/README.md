# Sieve S0 — 家庭网 AI / Agent 流量最小检测器

> Stage 0 原型。从 Pi-hole 的 DNS 查询日志里按设备找出 **LLM API / agent 基础设施 / DoH 绕过** 的痕迹，打分，超阈值推 Telegram 告警。
>
> **纯 Python 标准库，无需 `pip install`，树莓派开箱即跑。**

配套文档见上级目录的 `agent-trace-playbook.html`（紫队攻防手册）与 `sieve-console.html`（控制台设计）。

---

## 这是什么 / 不是什么

| 能做 | 不能做 |
|---|---|
| 抓内网设备访问 LLM API（影子 AI 外泄） | 看不到加密内容（没装 MITM 根证书） |
| 抓用系统 DNS 的本地 agent | 抓不到走 DoH/DoT 绕过你 DNS 的客户端 |
| 抓试图绕过你 DNS 的设备（连 DoH 解析器） | 不是"AI 内容审查"，是"异常行为检测" |

S0 只用 **DNS 这一个观测点**。想补上脚本客户端指纹（JA4）和回连体量，见手册里的 S2（Zeek + 镜像口）。

---

## 30 秒先看效果（无需 Pi-hole，Mac 上就能跑）

```bash
python3 sieve_s0.py --demo
```

会用一批合成数据跑一遍，输出类似：

```
192.168.1.77        分数= 95  [需查看]      ← 本地 agent：LLM 调用 + 域名爆发 + 规律回连
192.168.1.23        分数= 50  [告警]        ← 影子 AI：不该碰 LLM 的设备在发 api.openai.com
192.168.1.88        分数= 15  [正常]        ← 连了 DoH 解析器
192.168.1.50        分数=  0  [正常][白名单] ← 预期会用 LLM 的设备，已免分
```

---

## 真实部署（3 步）

### 1. 让 Pi-hole 当全网 DNS
在路由器 DHCP 设置里，把下发给客户端的 DNS 指向 Pi-hole 的 IP。这样每台设备的域名查询都会过 Pi-hole 并落进 `pihole-FTL.db`。

### 2. 把本目录放到 Pi-hole 所在机器上
```bash
cp config.example.json config.json
# 编辑 config.json：确认 pihole_db 路径、填 known_ai_clients（预期会用 LLM 的设备）
python3 sieve_s0.py --observe
```

> **头两周只用 `--observe`**，不要开告警。先让它把每台设备的正常敏感域名并入基线（`sieve_state.json`），否则第一周会被正常流量淹没。

### 3. 建好基线后开告警
```bash
export SIEVE_TG_TOKEN="123456:ABC..."     # 见下方 Telegram 设置
export SIEVE_TG_CHAT="你的 chat id"
python3 sieve_s0.py --alert
```

---

## 定时运行

### cron（每小时）
```cron
0 * * * * SIEVE_TG_TOKEN=... SIEVE_TG_CHAT=... /usr/bin/python3 /opt/sieve-s0/sieve_s0.py --alert >> /var/log/sieve-s0.log 2>&1
```

### systemd timer
`/etc/systemd/system/sieve-s0.service`
```ini
[Service]
Type=oneshot
Environment=SIEVE_TG_TOKEN=123456:ABC...
Environment=SIEVE_TG_CHAT=你的chatid
ExecStart=/usr/bin/python3 /opt/sieve-s0/sieve_s0.py --alert
```
`/etc/systemd/system/sieve-s0.timer`
```ini
[Timer]
OnCalendar=hourly
Persistent=true
[Install]
WantedBy=timers.target
```
```bash
sudo systemctl enable --now sieve-s0.timer
```

> 定时周期（如每小时）应与 `window_minutes` 一致，避免漏看或重复计。

---

## Telegram 设置

1. 找 **@BotFather** 新建 bot，拿到 token。
2. 给你的 bot 发一句话，然后访问
   `https://api.telegram.org/bot<token>/getUpdates`，在返回里找到 `chat.id`。
3. 填进环境变量 `SIEVE_TG_TOKEN` / `SIEVE_TG_CHAT`（优先级高于 config.json）。

不配置也能用——`--alert` 会打印告警内容但跳过推送。

---

## 命令行

```
--demo                 用合成数据演示，无需 Pi-hole
--observe              只打印不告警（建基线用）
--alert                超阈值推 Telegram
--window N             回看 N 分钟（覆盖配置里的 window_minutes）
--config PATH          指定配置文件（默认 ./config.json）
--no-color             禁用彩色输出
--no-baseline-update   本轮不写入基线
```

---

## 打分规则（可在 config.json 调）

| 信号 | 分 | 说明 |
|---|---|---|
| `llm_api` | +30 | 命中 LLM API 域名（白名单设备免计） |
| `agent_infra` | +20 | 命中 agent/抓取基础设施（白名单设备免计） |
| `beaconing` | +25 | 某敏感域名等间隔重复（间隔变异系数 CV ≤ 0.35） |
| `shadow_source` | +20 | 相对基线首次出现的敏感域名 |
| `fanout_burst` | +20 | 窗口内不同域名数 ≥ 40 |
| `doh_resolver` | +15 | 连已知 DoH 解析器（试图绕过你的 DNS） |

分数按设备在时间窗内累加。默认 **≥ 50 告警 · ≥ 80 需查看**。

调参：`weights`（各信号分值）、`fanout_threshold`、`beaconing_min_hits`、`beaconing_max_cv`、`alert_threshold`、`review_threshold`、`alert_cooldown_minutes`。

---

## 文件

| 文件 | 作用 |
|---|---|
| `sieve_s0.py` | 主程序 |
| `domains.txt` | LLM / agent / DoH 域名清单（自行增删，定期更新） |
| `config.example.json` | 配置模板，复制为 `config.json` |
| `sieve_state.json` | 运行时自动生成：每台设备的基线 + 告警冷却记录 |

---

## 下一步（对应手册）

- **S1**：对暴露的反代/NAS 日志，拉厂商官方 IP JSON 核验爬虫真伪。
- **S2**：镜像口 + Zeek 取 JA4 指纹，抓脚本客户端和回连 → 补上 S0 看不到的部分。
- **封 DoH**：在防火墙封 853 端口、拦截 `domains.txt` 里的 DoH 解析器域名，否则 DNS 这层随时被绕空。先跑手册里的测试 **T4** 看你现在是不是完全静默。

---

*仅用于你拥有或已获授权的网络。*
