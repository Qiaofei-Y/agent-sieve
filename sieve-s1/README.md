# Sieve S1 — 爬虫真伪核验（厂商官方 IP 段）

**简体中文** · [English](README.en.md)

> Stage 1 原型。对暴露在公网的服务（反代 / NAS / 博客）的访问日志，找出**自称是 AI 爬虫**
> 的请求（UA 含 GPTBot / ClaudeBot / PerplexityBot 等），用厂商**官方公布的 IP 段 JSON**
> 核验来源 IP 是否真的属于该厂商——UA 声称是 GPTBot 但 IP 不在官方段里 = 冒充。
>
> **纯 Python 标准库，无需 `pip install`，Mac / 树莓派开箱即跑。**

配套文档见上级目录的 `docs/`（紫队攻防手册、控制台设计）。

---

## 这是什么 / 不是什么

| 能做 | 不能做 |
|---|---|
| 核验自称 AI 爬虫的请求来源 IP 是否属于该厂商官方段 | 看不到没写明身份的爬虫（UA 伪装成普通浏览器） |
| 抓冒充 GPTBot/ClaudeBot/Perplexity 来扫站/薅内容的流量 | 不替你拦截——只做判定，处置交给防火墙/速率限制 |
| 用厂商官方 JSON 动态核验，不硬编码 IP，带缓存与超时 | 不解析加密内容，也不碰内网设备（那是 S0/S2 的活） |

S1 的观测点是**你自己服务的访问日志**（入站方向），与 S0（DNS 出站）、S2（TLS 指纹）互补。

---

## 30 秒先看效果（无需真实日志，Mac 上就能跑）

```bash
python3 sieve_s1.py --demo
```

会合成一段访问日志、在内存里注入"官方段"（不触网），输出类似：

```
Sieve S1 · 爬虫真伪核验报告   日志请求=9   自称爬虫=7
合计: verified=3 · spoofed=3 · unverifiable=1
------------------------------------------------------------------
GPTBot           (OpenAI)  verified=2 spoofed=2 unverifiable=0  源:demo
    [冒充] 45.137.21.9      "GET /wp-login.php HTTP/1.1"
    [冒充] 45.137.21.9      "POST /xmlrpc.php HTTP/1.1"
ClaudeBot        (Anthropic)  verified=0 spoofed=0 unverifiable=1  源:段取不到
    [无法核验] 185.220.101.5    "GET /docs/ HTTP/1.1"
PerplexityBot    (Perplexity)  verified=1 spoofed=1 unverifiable=0  源:demo
    [冒充] 103.224.182.251  "GET /.env HTTP/1.1"
------------------------------------------------------------------
⚑ 发现 3 条冒充 AI 爬虫的请求 —— 建议结合防火墙/速率限制处置。
```

- **verified**：真爬虫（UA 真 + IP 在官方段内）。
- **spoofed**：冒充（UA 真但 IP 不在官方段内）——重点看。
- **unverifiable**：官方 IP 段这次没取到（如 demo 未给 Anthropic 注入），降级跳过、不崩。

---

## 真实部署（3 步）

### 1. 准备访问日志
日志需为 **combined** 格式（含 User-Agent 字段，Nginx `log_format combined` / Apache `combined` 默认即是）。
common 格式没有 UA，无法核验，会被跳过。

> **在反代/CDN 之后？** 确保日志里记录的是**真实客户端 IP**而非反代内网 IP
> （Nginx 配 `set_real_ip_from` + `real_ip_header X-Forwarded-For`，或把 XFF 写进日志首字段）。
> 否则核验的是反代 IP，必然全部 spoofed。

### 2. 放到服务器上，复制配置
```bash
cp config.example.json config.json
# 编辑 config.json：确认 log_path，按需增删 bots / 调缓存 TTL
python3 sieve_s1.py --observe
```

首次运行会从各厂商官方 URL 拉取 IP 段并缓存到 `.cache/`（默认 TTL 24 小时）。
取不到就对该 bot 判 unverifiable 并打印提示，**不会中断**。

### 3. 建好节奏后开告警
```bash
export SIEVE_TG_TOKEN="123456:ABC..."     # Telegram 设置见 S0 的 README
export SIEVE_TG_CHAT="你的 chat id"
python3 sieve_s1.py --alert
```

不配置 Telegram 也能用——`--alert` 会打印告警内容但跳过推送。

---

## 定时运行（cron 每小时）

```cron
0 * * * * SIEVE_TG_TOKEN=... SIEVE_TG_CHAT=... /usr/bin/python3 /opt/sieve-s1/sieve_s1.py --log /var/log/nginx/access.log --alert >> /var/log/sieve-s1.log 2>&1
```

> 如需只看近期日志，先用 `logrotate` 切割，或对日志做 `tail` 后喂给 `--log`。

---

## 命令行

```
--demo                 用合成日志演示，无需真实日志，不触网
--observe              只打印不告警（默认）
--alert                冒充数超阈值推 Telegram
--log PATH             访问日志路径（覆盖配置里的 log_path）
--config PATH          指定配置文件（默认 ./config.json）
--rdns                 附带 forward-confirmed rDNS（FCrDNS）增强核验
--refresh-cache        忽略本地缓存，强制重新拉取官方 IP 段
--no-color             禁用彩色输出
```

---

## 核验逻辑

1. **挑出自称爬虫的请求**：逐行解析访问日志，UA 命中 `bots[].ua_tokens`（子串、大小写不敏感）即视为"自称某 bot"。
2. **取厂商官方 IP 段**：对该 bot 的 `ip_json_urls` 用 `urllib` 拉 JSON（带超时），本地缓存（`cache_dir`，`cache_ttl_hours` 内直接用）。失败则退回过期缓存，再不行就判 unverifiable。
3. **解析 CIDR**：用 `ipaddress` 从 JSON 里递归挖出所有 `ipv4Prefix / ipv6Prefix / prefix / cidr / ip` 等字段里的网段（兼容各家不同格式，不硬编码 IP）。
4. **比对来源 IP**：
   - IP ∈ 官方段 → **verified**
   - IP ∉ 官方段 → **spoofed**（告警）
   - 段取不到 → **unverifiable**（降级）
5. **可选 FCrDNS 增强**（`--rdns`）：对 IP 做 PTR 反查，命中厂商域名后缀且正向解析能回到同一 IP，才算 rDNS 通过；作为附注，不改变主判定（以 IP 段为准）。

---

## 字段说明（厂商官方 JSON URL）

| 厂商 | UA token | 官方 IP JSON |
|---|---|---|
| OpenAI | GPTBot | https://openai.com/gptbot.json |
| OpenAI | OAI-SearchBot | https://openai.com/searchbot.json |
| OpenAI | ChatGPT-User | https://openai.com/chatgpt-user.json |
| Anthropic | ClaudeBot 等 | https://claude.com/crawling/bots.json |
| Perplexity | PerplexityBot | https://www.perplexity.ai/perplexitybot.json |
| Perplexity | Perplexity-User | https://www.perplexity.ai/perplexity-user.json |

> URL 由厂商维护、偶有变动；在 `config.json` 的 `bots` 里自行增删维护，不要把 IP 写死进代码。

配置项：`log_path`、`cache_dir`、`cache_ttl_hours`、`fetch_timeout_seconds`、`enable_rdns`、`spoof_alert_threshold`（单个 bot 冒充数达到即告警）、`alert_cooldown_minutes`、`telegram`、`bots`。

---

## 文件

| 文件 | 作用 |
|---|---|
| `sieve_s1.py` | 主程序 |
| `config.example.json` | 配置模板，复制为 `config.json` |
| `.cache/` | 运行时自动生成：缓存的厂商官方 IP 段 JSON（不入库） |
| `sieve_s1_state.json` | 运行时自动生成：告警冷却记录（不入库） |

---

## 下一步（对应手册）

- **S0**：Pi-hole DNS 层——抓内网设备访问 LLM / agent（出站方向）。
- **S2**：Zeek + JA4 TLS 指纹——抓脚本客户端与回连。
- **S3**：把 S0 / S1 / S2 的判定合并研判。

---

*仅用于你拥有或已获授权的网络。*
