# Sieve S2 — TLS 指纹层检测器（Zeek + JA4）

> Stage 2 原型。在 S0（纯 DNS）之上补三件它看不到的事：
> **① 用 JA4 指纹判断客户端是不是脚本**（python/curl/go ≠ 真浏览器）；
> **② 从真实连接看回连节奏 beaconing**；**③ 看外发体量**。
>
> **纯 Python 标准库分析器**（无需 `pip install`）；采集侧需要一块跑 Zeek 的机器 + 一个流量镜像源。

配套：`../sieve-s0/`（DNS 层，复用其 `domains.txt`）、上级目录 `agent-trace-playbook.html`（紫队手册）。

---

## S2 补上了 S0 的哪块盲区

| | S0（DNS） | S2（TLS 指纹） |
|---|---|---|
| 看客户端是不是脚本 | ✗ | ✅ JA4 指纹 |
| 回连 beaconing | 只能靠 DNS 粗看 | ✅ 真实连接 + 字节 |
| 外发体量 / 外泄 | ✗ | ✅ orig_bytes |
| 被 DoH 绕过时 | 全盲 | ✅ IP 层仍可见 |

**诚实边界**：JA4 抓得住图省事的脚本（requests / urllib / curl / 扫描器），抓不住刻意用 `curl_cffi --impersonate chrome` / `tls-client` 伪造浏览器指纹的对手——那种会落到 `unknown` 或 `browser`。所以 JA4 是**信号之一**，要和"连了 LLM 域名 + 规律回连"叠加才构成高置信判断。这也是打分而非单规则的原因。

---

## 30 秒先看效果（无需 Zeek，Mac 上就能跑）

```bash
python3 sieve_s2.py --demo
```

合成一批 ssl/conn 日志跑一遍，输出类似：

```
192.168.1.99  分数=95 [需查看]  +40 非浏览器JA4  +30 LLM API  +25 规律回连
192.168.1.23  分数=70 [告警]    +40 非浏览器JA4(python→api.openai.com)
192.168.1.33  分数=60 [告警]    +40 非浏览器JA4(按IP连)  +20 大体量外发 90MB
192.168.1.50  分数= 0 [白名单]  浏览器 JA4，预期用 LLM，免分
```

（正常浏览器设备 192.168.1.11 分数 0，不出现在报告里。）

---

## 真实部署

### 1. 搞到一份流量镜像
把要监控的流量喂给 Zeek 所在网卡，三选一：
- **网管交换机 SPAN / 镜像口**（推荐）：把上联口镜像到接 Zeek 机器的口。
- **软路由**：OpenWRT/pfSense 上做端口镜像或直接在网关跑 Zeek。
- **旁路分光**（TAP）：最干净，但要硬件。

### 2. 装 Zeek + JA4 包
```bash
# Debian/树莓派示例
sudo apt install zeek zkg            # 或从 zeek.org 装
sudo zkg install zeek/ja4            # 官方 JA4 包，给 ssl.log 加 ja4 字段
```

### 3. 起 Zeek（JSON 日志 + JA4）
```bash
sudo zeek -i eth0 -C /opt/sieve-s2/zeek/sieve-ja4.zeek
# 日志写到当前目录；生产建议用 zeekctl 常驻，日志在 /opt/zeek/logs/current
```

### 4. 跑分析器
```bash
cp config.example.json config.json
# 编辑 config.json：zeek_logs_dir、local_nets（你的内网段）、known_ai_clients
python3 sieve_s2.py --observe --logs /opt/zeek/logs/current
```

头两周 `--observe`：顺便把反复出现的 JA4 对照设备确认，填进 `ja4_fingerprints.txt`（见下），之后再开 `--alert`。

---

## JA4 判定怎么工作

优先级：**标注表精确匹配 → 前缀匹配 → 结构启发式**。

启发式解析 JA4_a（下划线前那段，如 `t13d1516h2`）：TLS 版本、有无 SNI、密码套件数、扩展数、ALPN。打分标记：

| 标记 | 含义 |
|---|---|
| 无 ALPN（`00`） | 浏览器必带 ALPN，缺失是强脚本信号（+2） |
| 仅 HTTP/1.1（`h1`） | 现代浏览器会谈 h2（+1） |
| 扩展极少（≤8 / ≤11） | 原始库指纹（+2 / +1） |
| 无 SNI（按 IP 连，`i`） | 扫描/自动化（+1） |
| 仅 TLS≤1.2 | 老客户端/库（+1） |

≥3 → `automated`（疑似脚本）；=2 → 偏自动化；扩展多+h2 且无标记 → `browser`；其余 → `unknown`（宁可留空也不误判成浏览器）。

**建基线**：`ja4_fingerprints.txt` 里填入你在自己网络确认过的完整 JA4（如"这台就是 Chrome"），精确匹配会覆盖启发式，误报随之下降。不要盲抄外部硬编码指纹——客户端一升级指纹就变。

---

## 打分规则（config.json 可调）

| 信号 | 分 | 来源 |
|---|---|---|
| `non_browser_ja4` | +40 | ssl.log · JA4 判为 automated |
| `llm_api` | +30 | ssl.log · SNI 命中 LLM 域名 |
| `agent_infra` | +20 | ssl.log · SNI 命中 agent 基础设施 |
| `beaconing` | +25 | conn.log · 对某外部 IP 等间隔回连（CV≤0.35） |
| `large_egress` | +20 | conn.log · 单连外发 ≥ 50MB |
| `fanout_burst` | +20 | conn.log · 外部主机数 ≥ 40 |
| `doh_resolver` | +15 | ssl.log · SNI 命中 DoH 解析器 |

白名单设备（`known_ai_clients`）免计 JA4 / LLM / agent 分，但回连、外发、DoH 仍计。默认 **≥50 告警 · ≥80 需查看**。

---

## 定时运行

与 S0 相同（cron / systemd timer），把命令换成 `sieve_s2.py --alert` 即可。周期与 `window_minutes` 对齐。

---

## 文件

| 文件 | 作用 |
|---|---|
| `sieve_s2.py` | 分析器 |
| `zeek/sieve-ja4.zeek` | Zeek 站点配置（JSON + 加载 JA4 包） |
| `ja4_fingerprints.txt` | JA4 标注表（从自己网络基线里建） |
| `config.example.json` | 配置模板 |
| `sieve_s2_state.json` | 自动生成：告警冷却记录 |

---

## S0 + S2 怎么合起来看

两者都按设备打分、都推 Telegram。S0 从 DNS 侧、S2 从 TLS/连接侧，**同一台设备同时在两边冒头 = 高置信**。下一步（S3）就是把两路结果按设备合并、统一告警——留给后续。

现在就能做的最有价值的事：按手册 **T1–T7** 在自己网里自攻自检，看这两个脚本的误报/漏报，据此调 `weights` 和阈值。

---

*仅用于你拥有或已获授权的网络。*
