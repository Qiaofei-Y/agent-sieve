# Sieve Verify — 检测准确率验证 + 调参

> 在合并 S0/S2 之前，先用带 ground-truth 的数据把它们**量出来**：抓得准不准、
> 误报在哪、阈值该设多少。跑的是**真实的 S0/S2 打分代码**（直接 import），不是重写。

配套：`../sieve-s0/`（DNS 层）、`../sieve-s2/`（TLS 层）、上级目录 `agent-trace-playbook.html`（T1–T7 出处）。

---

## 为什么要先验证

Demo 里两个检测器都能抓明显的坏流量——但"能抓坏的"不等于"不冤枉好的"。
真正决定产品成不成立的是**误报**：把开发者正常用 ChatGPT 当成攻击，用户三天就卸载。
本阶段就是用"误报陷阱"把这件事量化出来。

---

## 30 秒看结论（Mac 上即可跑）

```bash
python3 evaluate.py
```

用内置标注集（4 个恶意场景 + 6 个良性陷阱）跑真实 S0/S2，输出实测结果：

| 检测层 | 精确率 | 召回率 | F1 | 误报 | 漏报 |
|---|---|---|---|---|---|
| **S0（纯 DNS）** | 75% | 75% | 0.75 | 1 | 1 |
| **S2（TLS 指纹）** | 100% | 100% | **1.00** | 0 | 0 |
| **并集 S0∪S2** | 80% | 100% | 0.89 | 1 | 0 |

### 这组数据得出的真结论

1. **S0 会冤枉人。** 开发者在浏览器里用 ChatGPT（B1）被 DNS 层打到 50 分 → 误报。
   因为 DNS 只看到"连了 openai.com"，分不清是人在浏览器点还是脚本在刷。
2. **S2 修好了它。** 同一台设备，JA4 指纹是浏览器 → 不加那 +40 → 30 分 → 正确放行；
   而脚本直连 LLM 的才被 +40 顶上去。**这就是当初要做 S2 的理由，现在被量化证明了。**
3. **两层缺一不可。** 纯 DoH 绕过（T4）没有 LLM 域名，S0 只给 15 分漏报；
   S2 靠"按 IP 连的脚本 JA4 +40"抓到。
4. **合并要当心**：并集在阈值 50 时继承了 S0 对 B1 的误报（取高分）；
   阈值扫描显示 **并集阈值提到 55、或不让 S0 单独触发告警 → F1 回到 1.00**。
   —— 这正是下一步 S3 合并该采用的规则，而不是盲目相加。

> 换句话说：**S3 合并 ≠ 两分相加。应以 S2 为主判、S0 为补召回，且要求"≥2 信号或 S2 命中"才告警。** 这是验证跑出来的，不是拍脑袋。

---

## 两种数据源

### A. 内置标注集（验证方法 + Mac 可跑）
`golden/` 下三份 JSON-lines + `labels.json`，带相对时间戳（运行时重基到当前），
刻意包含误报陷阱：

| 设备 | 标注 | 陷阱/场景 |
|---|---|---|
| 10.0.0.11 | benign | **浏览器用 ChatGPT**（DNS 层会误判） |
| 10.0.0.12 | benign | 备份客户端规律心跳（beaconing 陷阱） |
| 10.0.0.13 | benign | 重 CDN 站点（fanout 陷阱） |
| 10.0.0.14 | benign | 云盘上传大文件（large_egress 陷阱） |
| 10.0.0.50 | benign | 白名单开发机（测 known_ai_clients） |
| 10.0.0.23/77/88/99 | malicious | T1 外泄 / T5 agent / T4 DoH / T6 回连 |

可自行编辑这些文件加你关心的场景。

### B. 真实网络数据（调你自家参数）
```bash
# 1) 在网内机器用真实流量跑 T1–T7（见下），得到 attack_manifest.jsonl
# 2) 把 manifest 整理成 labels.json（client → {truth, scenario}）
# 3) 用真实 Pi-hole 库 + Zeek 日志重跑评估：
python3 evaluate.py --from-live \
    --pihole-db /etc/pihole/pihole-FTL.db \
    --zeek-logs /opt/zeek/logs/current \
    --labels labels.json --window 60
```
再据实测结果去改各模块 `config.json` 的 `weights` 和阈值。

---

## 真实网络自测：run_attacks.py

在**你自己的**网络里，从当前机器发出带标注的测试流量，让网内的 S0/S2 观测。

```bash
python3 run_attacks.py --list
python3 run_attacks.py --test t1 --yes                      # 影子外泄：python 直连 LLM API
python3 run_attacks.py --test t4 --yes                      # DoH 绕过
python3 run_attacks.py --test t6 --target 192.168.1.9       # 回连：等间隔连你自己的主机
python3 run_attacks.py --test t2 --target https://你的内网站/  # 脚本扒站
python3 run_attacks.py --test b1 --yes                      # 良性对照
```

每次运行追加一条 `attack_manifest.jsonl`（时间窗 + 标注），供你构造 labels。

**安全约束**：只对你拥有/授权的目标；默认只做 TLS 握手或未授权小请求，不发真实数据；
需要目标的测试（t2/t6）必须显式 `--target` 指向你自己的主机。T3/T5/T7 涉及外部工具或
真实 agent，见手册手动执行。

> 注：即便某次握手因本机证书库报错失败，**TLS ClientHello（携带 JA4 指纹 + SNI）已先行发出**，
> 检测器仍能观测到——测试意图依然达成。

---

## 文件

| 文件 | 作用 |
|---|---|
| `evaluate.py` | 评估器：import 真实 S0/S2 → 混淆矩阵 + P/R/F1 + 误报归因 + 阈值扫描 + 建议 |
| `run_attacks.py` | 真实网络自测流量生成器（T1/T2/T4/T6/B1） |
| `golden/*.jsonl`, `golden/labels.json` | 内置标注集（含误报陷阱，可编辑） |
| `attack_manifest.jsonl` | run_attacks 运行时生成 |

---

## 下一步：S3 合并（现在有依据了）

验证给出的合并规则：
- **以 S2 为主判**（精确率 100%），S0 作补召回（抓 S2 没 TLS 记录的场景）。
- **告警门槛**：S2 命中，或 S0+S2 同一设备"≥2 条独立信号"——不让 S0 单信号单独告警。
- 并集阈值按本评估取 **55**。
- 上线后定期用 `--from-live` 复测，随你网络变化重新调参。

---

*仅用于你拥有或已获授权的网络。*
