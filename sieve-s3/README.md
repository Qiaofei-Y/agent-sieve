# Sieve S3 — 合并层：S0(DNS) + S2(TLS) 统一研判

**简体中文** · [English](README.en.md)

> 把 DNS 侧（S0）和 TLS 侧（S2）两路信号按设备合并，套用 `../sieve-verify/` 跑出来的
> 研判规则做统一告警。**直接 import 真实的 S0/S2 打分代码**——单一事实源，合并层只做研判，不重算。

至此构成产品雏形：采集（Pi-hole + Zeek）→ 两层打分 → 合并研判 → 告警。

---

## 研判规则（不是两分相加）

验证阶段证明"两分相加"会把人类用 ChatGPT 误报。S3 改用：

| 规则 | 作用 |
|---|---|
| **S2 主判**：JA4 判为脚本（+40）→ 告警 | TLS 层精确率最高 |
| **S0 补召回**：抓 S2 没有 TLS 记录的场景 | 两层缺一不可 |
| **≥2 独立信号族 或 脚本确认** 才告警 | 不让 S0 单信号单独触发 |
| **人类护栏**：唯一证据是『连了 AI 域名』且 TLS 是浏览器 → 降为"观察" | 挡住 ChatGPT 误报 |
| **两层同时命中 = 高置信** | 对应"同一设备两边冒头" |

**独立信号族**：把同源证据归并，避免重复计数。
`llm`（LLM API / agent / 首次敏感域名）· `script`（非浏览器 JA4）· `beacon`（规律回连）·
`egress`（大外发）· `fanout`（扇出）· `doh`（DoH 绕过）。
"连了 openai.com + 首次出现"算 **1 个族**，不是 2 个——这正是挡住 ChatGPT 误报的关键。

研判级别：**告警**（推送）· **观察**（记录不推）· **正常** · **免分**（白名单）。

---

## 30 秒看效果（Mac 上即可跑）

```bash
python3 sieve_s3.py --demo
```

合并 S0 与 S2 两边的合成数据，输出类似：

```
192.168.1.99  告警 置信=高  (DNS 75/TLS 95)  [DNS][TLS] ⚑两层命中   LLM+回连+脚本JA4
192.168.1.33  告警 置信=中  (DNS  0/TLS 60)  [TLS]                脚本JA4+大外发
192.168.1.50  免分                                               白名单开发机
```

在 golden 标注集上实测：**FP=0, FN=0**（见 `../sieve-verify/`）。

---

## 真实部署

前提：S0（Pi-hole）与 S2（Zeek）都已按各自 README 跑起来。

```bash
cp config.example.json config.json
# 编辑：pihole_db、zeek_logs_dir、known_ai_clients
python3 sieve_s3.py --observe                 # 先看
export SIEVE_TG_TOKEN=... SIEVE_TG_CHAT=...
python3 sieve_s3.py --alert                   # 告警级设备推 Telegram
```

定时同 S0/S2（cron / systemd timer），命令换成 `sieve_s3.py --alert`。
S3 跑起来后，**不必再单独跑 S0/S2 的告警**——它已合并两者；S0/S2 可只留 `--observe` 供排查。

---

## 配置要点（来自验证结论，别随意回退）

| 键 | 默认 | 含义 |
|---|---|---|
| `union_threshold` | 55 | 并集（取两层高分）告警门槛 |
| `s2_automated_min` | 40 | S2 脚本确认的最低分（即 JA4=脚本本身） |
| `known_ai_clients` | — | 预期用 LLM 的设备，两层共用、统一免分 |
| `alert_cooldown_minutes` | 180 | 同设备告警去重 |

---

## 文件

| 文件 | 作用 |
|---|---|
| `sieve_s3.py` | 合并研判器（import S0/S2，产出统一告警） |
| `config.example.json` | 配置模板 |
| `sieve_s3_state.json` | 自动生成：告警冷却 |

---

## 整条流水线

```
采集          打分               合并            告警
Pi-hole  ─▶  S0 (DNS 信号)  ┐
                            ├─▶  S3 研判  ─▶  Telegram
Zeek+JA4 ─▶  S2 (TLS 信号)  ┘
                   ▲
          sieve-verify 持续用真实数据复测，反馈调参
```

上线后定期用 `../sieve-verify/evaluate.py --from-live` 复测，随网络变化重新调参。

---

*仅用于你拥有或已获授权的网络。*
