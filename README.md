<div align="center">

# 🧭 Sieve

**检测家庭网 / 内网里的 AI 与 Agent 异常流量痕迹**

影子 AI 外泄 · 脚本化抓取 · 自主 agent 回连 · DoH 绕过

[![license: MIT](https://img.shields.io/badge/license-MIT-0d7268)](LICENSE)
[![python](https://img.shields.io/badge/python-3.8%2B-0d7268)](#依赖)
[![deps: stdlib only](https://img.shields.io/badge/deps-stdlib%20only-0d7268)](#依赖)
[![status: prototype](https://img.shields.io/badge/status-prototype-eda100)](#路线图)

**简体中文** · [English](README.en.md)

</div>

---

Sieve 从网络侧检测 **AI / agent 的异常行为**——不是看它读了什么内容（路由器位置无 MITM 就看不到），
而是量"谁在用 AI、是人还是脚本、该不该告警"。两层观测（DNS + TLS 指纹）分别打分，合并研判，统一告警。

> **定位**：异常行为检测，不是内容审查。
> **边界**：仅用于你拥有或已获授权的网络。

```
采集                打分                    合并           告警
┌─────────┐   ┌──────────────────┐
│ Pi-hole │──▶│ S0  DNS 侧信号     │─┐
└─────────┘   └──────────────────┘  │   ┌──────────┐    ┌──────────┐
                                     ├──▶│ S3 研判   │───▶│ Telegram │
┌─────────┐   ┌──────────────────┐  │   └──────────┘    └──────────┘
│Zeek+JA4 │──▶│ S2  TLS 侧信号     │─┘        ▲
└─────────┘   └──────────────────┘           │
                       sieve-verify 用真实数据持续复测、反馈调参
```

## ⚡ 60 秒上手（无需任何基础设施）

```bash
git clone https://github.com/Qiaofei-Y/agent-sieve.git && cd agent-sieve
python3 sieve-s0/sieve_s0.py --demo       # DNS 层
python3 sieve-s2/sieve_s2.py --demo       # TLS 指纹层
python3 sieve-verify/evaluate.py          # 准确率评估（含误报陷阱）
python3 sieve-s3/sieve_s3.py --demo       # 合并研判
# 或一键：
make demo
```

全部纯 Python 标准库，**无需 `pip install`**。

## 🧩 组成

| 目录 | 是什么 | 状态 |
|---|---|---|
| [`sieve-s0/`](sieve-s0/) | **S0** · Pi-hole DNS 层检测器 | ✅ |
| [`sieve-s2/`](sieve-s2/) | **S2** · Zeek + JA4 TLS 指纹层检测器 | ✅ |
| [`sieve-s3/`](sieve-s3/) | **S3** · 合并研判，统一告警 | ✅ |
| [`sieve-verify/`](sieve-verify/) | 准确率验证 + 调参（跑真实 S0/S2 代码） | ✅ |
| [`docs/`](docs/) | 攻防手册、验证运行手册、控制台设计（HTML） | — |

每个组件都能独立运行，不必等全套建成。各目录有自己的 README。

## 🧠 设计结论（都是 [`sieve-verify`](sieve-verify/) 量出来的）

1. **纯 DNS 会冤枉人**：开发者浏览器用 ChatGPT 会被 DNS 层误判（F1 0.75）。
2. **TLS 指纹修好它**：JA4 区分脚本/浏览器，S2 精确率 100%。
3. **两层缺一不可**：纯 DoH 绕过无 LLM 域名，靠 S2 脚本指纹才抓到。
4. **合并 ≠ 相加**：S3 用"S2 主判 + ≥2 信号族 + 人类护栏"，golden 集上 **FP=0 FN=0**。

诚实边界：`curl_cffi` 等能伪造浏览器 JA4（抓得住图省事的脚本，抓不住刻意伪装的）；
DoH/ECH 在收窄视野，须在防火墙封 DoH。详见 [攻防手册](docs/agent-trace-playbook.html)。

## 🚀 真实部署

1. 路由器 DHCP 把 DNS 指向 Pi-hole → `sieve-s0 --observe` **观察两周**建基线。
2. 交换机 SPAN 口 + 树莓派跑 Zeek（`zkg install zeek/ja4`）→ `sieve-s2 --observe`。
3. 按 [验证运行手册](docs/validation-runbook.html) 跑 T1–T7 自测，用 `sieve-verify` 量误报/漏报、调参。
4. 两层就位后 `sieve-s3 --alert` 统一告警。

> 📋 完整验证流程见交互式 **[验证运行手册](docs/validation-runbook.html)**（可勾选 + 自动算准确率）。

## 📎 依赖

- Python 3.8+（标准库，无第三方包）
- 运行时：[Pi-hole](https://pi-hole.net/)（S0）、[Zeek](https://zeek.org/) + [`zeek/ja4`](https://github.com/FoxIO-LLC/ja4)（S2）
- 告警：Telegram Bot（可选）

## 🗺 路线图

- [x] S0 DNS 层 · S2 TLS 层 · S3 合并 · 验证框架
- [ ] 真实网络验证，产出实测精确率
- [ ] S1 爬虫真伪核验（厂商 IP JSON）
- [ ] 跨客户域名信誉库 / JA4 指纹库（护城河）
- [ ] 托管版 / Web 控制台

## 🤝 贡献 & 安全

见 [CONTRIBUTING.md](CONTRIBUTING.md) 与 [SECURITY.md](SECURITY.md)。
最有价值的贡献：补充 [`domains.txt`](sieve-s0/domains.txt) 的 LLM/agent 域名、
以及你网络里确认过的 JA4 指纹。

## 📄 许可

[MIT](LICENSE) · 仅用于你拥有或已获授权的网络。
